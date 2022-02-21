package br.com.alura.forum.controller;

import java.net.URI;
import java.util.Optional;

import javax.transaction.Transactional;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import br.com.alura.forum.controller.dto.DetalhesDoTopicoDto;
import br.com.alura.forum.controller.dto.TopicoDto;
import br.com.alura.forum.controller.form.AtualizcaoTopicoForm;
import br.com.alura.forum.controller.form.TopicoForm;
import br.com.alura.forum.modelo.Topico;
import br.com.alura.forum.repository.CursoRepository;
import br.com.alura.forum.repository.TopicoRepository;

@RestController
@RequestMapping("/topicos")
public class TopicosController {
	
	@Autowired
	private TopicoRepository topicoRepository;
	
	@Autowired
	private CursoRepository cursoRep;
	
	@GetMapping
	@Cacheable(value = "listaDeTopicos")
	public Page<TopicoDto> lista(@RequestParam(required = false) String nomeCurso,
			@PageableDefault(page = 0, size = 10, sort = "id", direction = Direction.DESC)  Pageable paginacao) {
		// <Pageable paginacao> está substituindo <@RequestParam int pagina, @RequestParam int qtd, @RequestParam String ordenacao>
		// Precisa habilitar módulo web no main.
			
		if (nomeCurso == null) {
			Page<Topico> topicos = topicoRepository.findAll(paginacao);
			return TopicoDto.converter(topicos);
		} else {
			Page<Topico> topicos = topicoRepository.findByCursoNome(nomeCurso, paginacao);
			return TopicoDto.converter(topicos);
		}
	}
	
	//salva um novo tópico no BD
	@Transactional // Avisa ao Spring para realizar commit ao fim da execução do método.
	@PostMapping
	@CacheEvict(value = "listaDeTopicos", allEntries = true)
	public ResponseEntity<TopicoDto> cadastrar(@RequestBody @Valid TopicoForm form, UriComponentsBuilder uriBuilder) { //retorna COD 201
		Topico topico = form.converter(cursoRep);
		topicoRepository.save(topico);
		
		// o parâmetro é dinâmico, baseado no id dentro de chaves.
		URI uri = uriBuilder.path("/topicos/{id}").buildAndExpand(topico.getId()).toUri();
		return ResponseEntity.created(uri).body(new TopicoDto(topico)); // o retorno precisa de uma Uri e um corpo (body).
	}
	
	//pesquisa topico por ID, trazendo informações detalhadas deste.
	@GetMapping("/{id}")
	public ResponseEntity<DetalhesDoTopicoDto> detalhar(@PathVariable Long id) { 
		Optional<Topico> topico = topicoRepository.findById(id);
		if(topico.isPresent()) {
			return ResponseEntity.ok(new DetalhesDoTopicoDto(topico.get()));		
		}
		
		return ResponseEntity.notFound().build();
	}

	//atualizar um tópico específico no BD
	@Transactional 
	@PutMapping("/{id}")
	@CacheEvict(value = "listaDeTopicos", allEntries = true)
	public ResponseEntity<TopicoDto> atualizar(@PathVariable Long id, @RequestBody @Valid AtualizcaoTopicoForm form){
		Optional<Topico> optional = topicoRepository.findById(id);		
		if(optional.isPresent()) {
			Topico topico = form.atualizar(id,topicoRepository);
			return ResponseEntity.ok(new TopicoDto(topico));
		}
		
		return ResponseEntity.notFound().build();
		
		//na linha acima as atualizações no "topico" em questão foram feitas em memória local. Com o @Transactional, o Spring commita as transações ao 
		//final de cada método e a JPA irá detectar que foram feitas alterações em uma entidade do banco e irá salvar automaticamente.
	}
	
	//deletando do banco de dados por ID.
	@Transactional
	@DeleteMapping("/{id}")
	@CacheEvict(value = "listaDeTopicos", allEntries = true)
	public ResponseEntity<?> remover (@PathVariable Long id) {
		Optional<Topico> optional = topicoRepository.findById(id);
		
		if(optional.isPresent()) {
			topicoRepository.deleteById(id);
			return ResponseEntity.ok().build();
		}
		
		return ResponseEntity.notFound().build();
		
	}
}