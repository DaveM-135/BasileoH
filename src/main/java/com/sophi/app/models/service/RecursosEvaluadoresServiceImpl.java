package com.sophi.app.models.service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.mail.dto.MailRequest;
import com.sophi.app.mail.dto.MailResponse;
import com.sophi.app.mail.service.EmailService;
import com.sophi.app.models.dao.IRecursoEvaluadorDao;
import com.sophi.app.models.entity.EvaluacionDesempeno;
import com.sophi.app.models.entity.LiderProyectoEvaluacion;
import com.sophi.app.models.entity.Recurso;
import com.sophi.app.models.entity.RecursoEvaluacion;
import com.sophi.app.models.entity.RecursoEvaluador;

@Service
public class RecursosEvaluadoresServiceImpl implements IRecursosEvaluadoresService {
	
	@Autowired
	private ICapHoraService capHoraService;
	
	@Autowired
	private IRecursoEvaluacionService recursoEvaluacionService;
	
	@Autowired
	private IRecursoEvaluadorDao recursoEvaluadorDao;
	
	@Autowired
	private IRecursoService recursoService;
	
	@Autowired
	private IEvaluacionDesempenoService evaluacionService;
	
	@Autowired
	private EmailService service;
	
	@Async
	public void evaluadoresRecurso(List<RecursoEvaluacion> listaRecursosEvaluacion) {
		for (RecursoEvaluacion recursoEvaluacion : listaRecursosEvaluacion) {
			System.out.println("Evaluado: " + recursoEvaluacion.getDescRecurso() + " - " + recursoEvaluacion.getEvaluacionDesempeno().getCodEvaluacionDesempeno());
			guardarEvaluadoresRecursoTemporales(recursoEvaluacion);
		}
	}
	
	@Async
	public void guardarEvaluadoresRecursoTemporales(RecursoEvaluacion re) {
		List<LiderProyectoEvaluacion> aprobadores = capHoraService.findCodAprobadoresByCodRecursoAndFechaInicioAndFechaFin(re.getCodRecurso(), re.getEvaluacionDesempeno().getFecPeriodoInicio(), re.getEvaluacionDesempeno().getFecPeriodoFin());
		List<RecursoEvaluador> listaRecursoEvaluador = new ArrayList<>();
		for (LiderProyectoEvaluacion aprobador : aprobadores) {
			RecursoEvaluador recursoEvaluador = new RecursoEvaluador(re.getEvaluacionDesempeno(), re.getCodRecurso(), re.getDescRecurso(), aprobador.getCodRecursoLider(), aprobador.getNombreRecursoLider(), aprobador.getMailRecursoLider());
			recursoEvaluador.setCodEvaluacionDesempeno(re.getEvaluacionDesempeno().getCodEvaluacionDesempeno());
			recursoEvaluador.setDescEvaluador(recursoService.getNombreApellidoById(aprobador.getCodRecursoLider()));
			recursoEvaluador.setDescMailEvaluador(recursoService.getEmailRecursoById(aprobador.getCodRecursoLider()));
			listaRecursoEvaluador.add(recursoEvaluador);
		}
		guardarAll(listaRecursoEvaluador);
	}
	
	@Async
	public void notificacionInicioEvaluacion(List<RecursoEvaluacion> listaRecursosEvaluacion) {
		for (RecursoEvaluacion recursoEvaluacion : listaRecursosEvaluacion) {
			Recurso recurso = recursoService.findOne(recursoEvaluacion.getCodRecurso());
			EvaluacionDesempeno evaluacionDesempeno = evaluacionService.findById(recursoEvaluacion.getEvaluacionDesempeno().getCodEvaluacionDesempeno());
			//Aprobador INICIO 
			MailRequest request = new MailRequest();
			request.setName(recurso.getDescRecurso());
			request.setSubject("Inicio de evaluaciones de desempeño");
			request.setTo(recurso.getDescCorreoElectronico());
			
			Map<String, Object> modelM = new HashMap<String, Object>();
			modelM.put("nombreRecurso", request.getName());
			modelM.put("mensaje", "<h3>Ha iniciado el periodo de evaluaciones de desempeño \""+ evaluacionDesempeno.getDescEvaluacionDesempeno() + "\", ya puedes iniciar tu autoevaluci&oacute;n en la secci&oacute;n Evaluaci&oacute;n de desempe&ntilde;o > Mis evaluaciones dentro de la plataforma.</h3>.");
			modelM.put("imagen","<img data-cfsrc=\"images/img-evaluaciones.png\" alt=\"\" data-cfstyle=\"width: 200px; max-width: 400px; height: auto; margin: auto; display: block;\" style=\"width: 200px; max-width: 400px; height: auto; margin: auto; display: block;\" src=\"https://sophitech.herokuapp.com/img/img-evaluaciones.png\">");
			modelM.put("btnLink", "<a href=\"https://sophitech.herokuapp.com/misEvaluaciones\" style=\"text-align: center; border-radius: 5px; font-weight: bold; background-color: #C02C57; color: white; padding: 14px 25px; text-decoration: none; display: inline-block; \">Mis evaluaciones</a>");
			modelM.put("pie", "Muchas gracias por tu apoyo");
			
			MailResponse response = service.sendEmailEvaluador(request, modelM);
			System.out.println(response.getMessage());
			//Aprobador FIN
		}
	}
	
	@Async
	public void notificacionFinEvaluacion(List<RecursoEvaluacion> listaRecursosEvaluacion) {
		for (RecursoEvaluacion recursoEvaluacion : listaRecursosEvaluacion) {
			Recurso recurso = recursoService.findOne(recursoEvaluacion.getCodRecurso());
			EvaluacionDesempeno evaluacionDesempeno = evaluacionService.findById(recursoEvaluacion.getEvaluacionDesempeno().getCodEvaluacionDesempeno());
			//Aprobador INICIO 
			MailRequest request = new MailRequest();
			request.setName(recurso.getDescRecurso());
			request.setSubject("Cierre de evaluaciones de desempeño");
			request.setTo(recurso.getDescCorreoElectronico());
			
			Map<String, Object> modelM = new HashMap<String, Object>();
			modelM.put("nombreRecurso", request.getName());
			modelM.put("mensaje", "<h3>Ha finalizado el periodo de evaluaciones de desempeño \""+ evaluacionDesempeno.getDescEvaluacionDesempeno() + "\", puedes consultar tus resultados en la secci&oacute;n Evaluaci&oacute;n de desempe&ntilde;o > Mis evaluaciones dentro de la plataforma.<br><br>Espera tu retroalimentaci&oacute;n.</h3>.");
			modelM.put("imagen","<img data-cfsrc=\"images/img-evaluaciones.png\" alt=\"\" data-cfstyle=\"width: 200px; max-width: 400px; height: auto; margin: auto; display: block;\" style=\"width: 200px; max-width: 400px; height: auto; margin: auto; display: block;\" src=\"https://sophitech.herokuapp.com/img/img-evaluaciones.png\">");
			modelM.put("btnLink", "<a href=\"https://sophitech.herokuapp.com/misEvaluaciones\" style=\"text-align: center; border-radius: 5px; font-weight: bold; background-color: #C02C57; color: white; padding: 14px 25px; text-decoration: none; display: inline-block; \">Mis evaluaciones</a>");
			modelM.put("pie", "Muchas gracias por participar");
			
			MailResponse response = service.sendEmailEvaluador(request, modelM);
			System.out.println(response.getMessage());
			//Aprobador FIN
		}
	}
	
	
	@Async
	public void guardarEvaluadoresRecurso(RecursoEvaluacion re) {
		List<RecursoEvaluador> listaEvaluadoresTemp = findByCodEvaluacionDesempenoAndCodRecurso(re.getCodEvaluacionDesempeno(), re.getCodRecurso());
		List<RecursoEvaluacion> listaEvaluadores = new ArrayList<>();
		for (RecursoEvaluador aprobador : listaEvaluadoresTemp) {
			RecursoEvaluacion evaluador = new RecursoEvaluacion();
			evaluador.setCodRecurso(re.getCodRecurso());
			evaluador.setDescRecurso(re.getDescRecurso());
			evaluador.setCodEvaluacionDesempeno(re.getEvaluacionDesempeno().getCodEvaluacionDesempeno());
			evaluador.setEvaluacionDesempeno(re.getEvaluacionDesempeno());
			evaluador.setValResultadoMetas(re.getValResultadoMetas());
			evaluador.setValResultadoCompetencias(0L);
			evaluador.setValResultadoGeneral(0L);
			evaluador.setCodRecursoEvaluador(aprobador.getCodEvaluador());
			evaluador.setValTipoEvaluador(2L);
			evaluador.setValEstatus(1L);
			evaluador.setDescEstatus("no iniciada");
			listaEvaluadores.add(evaluador);
			
			//MAIL INICIO
//			Recurso recurso = recursoService.findOne(aprobador.getCodRecursoEvaluador());
			EvaluacionDesempeno evaluacionDesempeno = evaluacionService.findById(re.getEvaluacionDesempeno().getCodEvaluacionDesempeno());
			//Aprobador INICIO 
			MailRequest request = new MailRequest();
			request.setName(aprobador.getDescEvaluador());
			request.setSubject("Evaluación de recursos");
			request.setTo(aprobador.getDescMailEvaluador());
			
			Map<String, Object> modelM = new HashMap<String, Object>();
			modelM.put("nombreRecurso", request.getName());
			modelM.put("mensaje", "<h3>"+ re.getDescRecurso() + " ha concluido su autoevaluaci&oacute;n de la evaluaci&oacute;n \""+ evaluacionDesempeno.getDescEvaluacionDesempeno()+"\", ya puedes iniciar la evaluaci&oacute;n en la secci&oacute;n Evaluaci&oacute;n de desempe&ntilde;o > Mis evaluados dentro de la plataforma.\"</h3>.");
			modelM.put("imagen","<img data-cfsrc=\"images/img-evaluaciones.png\" alt=\"\" data-cfstyle=\"width: 200px; max-width: 400px; height: auto; margin: auto; display: block;\" style=\"width: 200px; max-width: 400px; height: auto; margin: auto; display: block;\" src=\"https://sophitech.herokuapp.com/img/img-evaluaciones.png\">");
			modelM.put("btnLink", "<a href=\"https://sophitech.herokuapp.com/misEvaluados\" style=\"text-align: center; border-radius: 5px; font-weight: bold; background-color: #C02C57; color: white; padding: 14px 25px; text-decoration: none; display: inline-block; \">Mis evaluados</a>");
			modelM.put("pie", "Muchas gracias por tu apoyo");
			
			MailResponse response = service.sendEmailAutoevaluacionCompleta(request, modelM);
			System.out.println(response.getMessage());
			//MAIL FIN
		}
		recursoEvaluacionService.guardarAll(listaEvaluadores);
	}


	@Override
	@Transactional
	public void guardar(RecursoEvaluador recursoEvaluador) {
		recursoEvaluadorDao.save(recursoEvaluador);
	}


	@Override
	@Transactional
	public void guardarAll(List<RecursoEvaluador> listRecursosEvaluadores) {
		recursoEvaluadorDao.saveAll(listRecursosEvaluadores);
	}


	@Override
	@Transactional(readOnly = true)
	public RecursoEvaluador findById(Long codRecursoEvaluador) {
		return recursoEvaluadorDao.findById(codRecursoEvaluador).orElse(null);
	}


	@Override
	@Transactional(readOnly = true)
	public List<RecursoEvaluador> findByCodEvaluacionDesempenoAndCodRecurso(Long codEvaluacionDesempeno, Long codRecurso) {
		return recursoEvaluadorDao.findByCodEvaluacionDesempenoAndCodRecurso(codEvaluacionDesempeno , codRecurso);
	}


	@Override
	@Transactional(readOnly = true)
	public List<RecursoEvaluador> findByCodEvaluacionDesempenoAndCodEvaluador(Long codEvaluacionDesempeno, Long codEvaluador) {
		return recursoEvaluadorDao.findByCodEvaluacionDesempenoAndCodEvaluador(codEvaluacionDesempeno, codEvaluador);
	}


	@Override
	@Transactional
	public void deleteById(Long codRecursoEvaluador) {
		recursoEvaluadorDao.deleteById(codRecursoEvaluador);
	}

	@Override
	@Transactional(readOnly = true)
	public List<RecursoEvaluador> findByCodEvaluacionDesempeno(Long codEvaluacionDesempeno) {
		return recursoEvaluadorDao.findByCodEvaluacionDesempeno(codEvaluacionDesempeno);
	}

	@Override
	@Transactional
	public void deleteRecursoEvaluadorByCodRecursoAndCodEvaluacion(Long codRecurso, Long codEvaluacionDesempeno) {
		recursoEvaluadorDao.deleteRecursoEvaluadorByCodRecursoAndCodEvaluacion(codRecurso, codEvaluacionDesempeno);
	}

}
