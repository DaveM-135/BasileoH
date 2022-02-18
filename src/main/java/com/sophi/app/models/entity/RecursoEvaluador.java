package com.sophi.app.models.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.PrePersist;
import javax.persistence.Table;

@Entity
@Table(name = "RECURSOS_EVALUADOR")
public class RecursoEvaluador implements Serializable  {

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_recurso_evaluador")
	private Long codRecursoEvaluador;
	
	@Column(name = "cod_evaluacion_desempeno")
	private Long codEvaluacionDesempeno;
	
	@Column(name = "cod_recurso")
	private Long codRecurso;
	
	@Column(name = "desc_recurso")
	private String descRecurso;
	
	@Column(name = "cod_evaluador")
	private Long codEvaluador;
	
	@Column(name = "desc_evaluador")
	private String descEvaluador;
	
	@Column(name = "desc_mail_evaluador")
	private String descMailEvaluador;
	
	@Column(name = "val_confirmado")
	private Long valConfirmado;
	
	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "cod_evaluacion_desempeno", insertable=false, updatable=false)
	private EvaluacionDesempeno evaluacionDesempeno;
	
	@PrePersist
	public void prePersist() {
		valConfirmado = 0L;
	}
	
	public RecursoEvaluador(){
		
	}

	public RecursoEvaluador(EvaluacionDesempeno evaluacionDesempeno, Long codRecurso, String descRecurso, Long codEvaluador,
			String descEvaluador, String descMailEvaluador) {
		super();
		this.evaluacionDesempeno = evaluacionDesempeno;
		this.codRecurso = codRecurso;
		this.descRecurso = descRecurso;
		this.codEvaluador = codEvaluador;
		this.descEvaluador = descEvaluador;
		this.descMailEvaluador = descMailEvaluador;
	}
	
	public Long getCodRecursoEvaluador() {
		return codRecursoEvaluador;
	}

	public void setCodRecursoEvaluador(Long codRecursoEvaluador) {
		this.codRecursoEvaluador = codRecursoEvaluador;
	}

	public EvaluacionDesempeno getEvaluacionDesempeno() {
		return evaluacionDesempeno;
	}

	public void setEvaluacionDesempeno(EvaluacionDesempeno evaluacionDesempeno) {
		this.evaluacionDesempeno = evaluacionDesempeno;
	}

	public Long getCodEvaluacionDesempeno() {
		return codEvaluacionDesempeno;
	}

	public void setCodEvaluacionDesempeno(Long codEvaluacionDesempeno) {
		this.codEvaluacionDesempeno = codEvaluacionDesempeno;
	}

	public Long getCodRecurso() {
		return codRecurso;
	}

	public void setCodRecurso(Long codRecurso) {
		this.codRecurso = codRecurso;
	}

	public String getDescRecurso() {
		return descRecurso;
	}

	public void setDescRecurso(String descRecurso) {
		this.descRecurso = descRecurso;
	}

	public Long getCodEvaluador() {
		return codEvaluador;
	}

	public void setCodEvaluador(Long codEvaluador) {
		this.codEvaluador = codEvaluador;
	}

	public String getDescEvaluador() {
		return descEvaluador;
	}

	public void setDescEvaluador(String descEvaluador) {
		this.descEvaluador = descEvaluador;
	}

	public String getDescMailEvaluador() {
		return descMailEvaluador;
	}

	public void setDescMailEvaluador(String descMailEvaluador) {
		this.descMailEvaluador = descMailEvaluador;
	}

	public Long getValConfirmado() {
		return valConfirmado;
	}

	public void setValConfirmado(Long valConfirmado) {
		this.valConfirmado = valConfirmado;
	}

}
