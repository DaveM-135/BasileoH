package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.persistence.Transient;

@Entity
@Table(name = "RECURSOS_EVALUACIONES")
public class RecursoEvaluacion implements Serializable {

	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_recurso_evaluacion")
	private Long codRecursoEvaluacion; 
	
	@Column(name = "cod_recurso")
	private Long codRecurso;
	
	@Column(name = "desc_recurso")
	private String descRecurso;
	
	@Column(name = "cod_evaluacion_desempeno")
	private Long codEvaluacionDesempeno;
	
	@Column(name = "val_resultado_metas")
	private float valResultadoMetas;
	
	@Column(name = "val_resultado_competencias")
	private float valResultadoCompetencias;
	
	@Column(name = "val_resultado_general")
	private float valResultadoGeneral;
	
	@Column(name = "cod_recurso_evaluador")
	private Long codRecursoEvaluador;
	
	@Column(name = "val_tipo_evaluador")
	private Long valTipoEvaluador;
	
	@Column(name = "val_estatus")
	private Long valEstatus;
	
	@Column(name = "desc_estatus")
	private String descEstatus;
	
	@Transient
	private String evaluadoresConcat;
	
	@Transient
	private String estatusGeneral;
	
	@Transient
	private Long valEstatusGeneral;
	
	@Transient
	private Float promedioCompetencias;
	
	@Transient
	private Float valResultadoEmpresa;
	
	@Transient
	private Float valResultadoFinal;
	
	@Transient
	private List<RespuestaCompetencia> respuestasCompetencias;
	
	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "cod_evaluacion_desempeno", insertable=false, updatable=false)
	private EvaluacionDesempeno evaluacionDesempeno;
	
	public Long getCodRecursoEvaluacion() {
		return codRecursoEvaluacion;
	}

	public void setCodRecursoEvaluacion(Long codRecursoEvaluacion) {
		this.codRecursoEvaluacion = codRecursoEvaluacion;
	}

	public Long getCodRecurso() {
		return codRecurso;
	}

	public void setCodRecurso(Long codRecurso) {
		this.codRecurso = codRecurso;
	}

	public Long getCodEvaluacionDesempeno() {
		return codEvaluacionDesempeno;
	}

	public void setCodEvaluacionDesempeno(Long codEvaluacionDesempeno) {
		this.codEvaluacionDesempeno = codEvaluacionDesempeno;
	}

	public EvaluacionDesempeno getEvaluacionDesempeno() {
		return evaluacionDesempeno;
	}

	public void setEvaluacionDesempeno(EvaluacionDesempeno evaluacionDesempeno) {
		this.evaluacionDesempeno = evaluacionDesempeno;
	}

	public String getDescRecurso() {
		return descRecurso;
	}

	public void setDescRecurso(String descRecurso) {
		this.descRecurso = descRecurso;
	}

	public float getValResultadoMetas() {
		return valResultadoMetas;
	}

	public void setValResultadoMetas(float valResultadoMetas) {
		this.valResultadoMetas = valResultadoMetas;
	}

	public float getValResultadoCompetencias() {
		return valResultadoCompetencias;
	}

	public void setValResultadoCompetencias(float valResultadoCompetencias) {
		this.valResultadoCompetencias = valResultadoCompetencias;
	}

	public Long getCodRecursoEvaluador() {
		return codRecursoEvaluador;
	}

	public void setCodRecursoEvaluador(Long codRecursoEvaluador) {
		this.codRecursoEvaluador = codRecursoEvaluador;
	}

	public Long getValTipoEvaluador() {
		return valTipoEvaluador;
	}

	public void setValTipoEvaluador(Long valTipoEvaluador) {
		this.valTipoEvaluador = valTipoEvaluador;
	}

	public Long getValEstatus() {
		return valEstatus;
	}

	public void setValEstatus(Long valEstatus) {
		this.valEstatus = valEstatus;
	}

	public String getDescEstatus() {
		return descEstatus;
	}

	public void setDescEstatus(String descEstatus) {
		this.descEstatus = descEstatus;
	}

	public float getValResultadoGeneral() {
		return valResultadoGeneral;
	}

	public void setValResultadoGeneral(float valResultadoGeneral) {
		this.valResultadoGeneral = valResultadoGeneral;
	}

	public String getEvaluadoresConcat() {
		return evaluadoresConcat;
	}

	public void setEvaluadoresConcat(String evaluadoresConcat) {
		this.evaluadoresConcat = evaluadoresConcat;
	}

	public List<RespuestaCompetencia> getRespuestasCompetencias() {
		return respuestasCompetencias;
	}

	public void setRespuestasCompetencias(List<RespuestaCompetencia> respuestasCompetencias) {
		this.respuestasCompetencias = respuestasCompetencias;
	}

	public Float getPromedioCompetencias() {
		return promedioCompetencias;
	}

	public void setPromedioCompetencias(Float promedioCompetencias) {
		this.promedioCompetencias = promedioCompetencias;
	}

	public String getEstatusGeneral() {
		return estatusGeneral;
	}

	public void setEstatusGeneral(String estatusGeneral) {
		this.estatusGeneral = estatusGeneral;
	}

	public Long getValEstatusGeneral() {
		return valEstatusGeneral;
	}

	public void setValEstatusGeneral(Long valEstatusGeneral) {
		this.valEstatusGeneral = valEstatusGeneral;
	}

	public Float getValResultadoEmpresa() {
		return valResultadoEmpresa;
	}

	public void setValResultadoEmpresa(Float valResultadoEmpresa) {
		this.valResultadoEmpresa = valResultadoEmpresa;
	}

	public Float getValResultadoFinal() {
		return valResultadoFinal;
	}

	public void setValResultadoFinal(Float valResultadoFinal) {
		this.valResultadoFinal = valResultadoFinal;
	}

	
}
