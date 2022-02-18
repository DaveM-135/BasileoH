package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.Date;

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
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

import com.sophi.app.Utiles;

@Entity
@Table(name = "DETALLE_EVALUACION_PROYECTO")
public class DetalleEvaluacionProyecto implements Serializable{

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_evaluacion_proyecto")
	private Long codEvaluacionProyecto;
	
//	@Column(name = "cod_concepto")
//	private Long codConcepto;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "cod_concepto")
	private Concepto concepto;
//	
//	@ManyToOne(fetch = FetchType.LAZY)
//	@JoinColumn(name = "cod_evaluacion")
//	private Evaluacion evaluacion;
	
	@Column(name = "cod_evaluacion")
	private Long codEvaluacion;
	
	@Column(name = "cod_proyecto")
	private Long codProyecto;
	
	@Column(name = "desc_comentario")
	private String descComentario;
	
	@Column(name = "ruta")
	private String ruta;
	
	@Column(name = "cod_recurso_evaluador")
	private Long codRecursoEvaluador;
	
	@Column(name = "calificacion")
	private float calificacion;
	
	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	private Date fecRegistro;
	
	@PrePersist
	public void prePersist() {
		fecRegistro = new Utiles().getFechaActual();
	}

	public Long getCodEvaluacionProyecto() {
		return codEvaluacionProyecto;
	}

	public void setCodEvaluacionProyecto(Long codEvaluacionProyecto) {
		this.codEvaluacionProyecto = codEvaluacionProyecto;
	}

//	public Long getCodConcepto() {
//		return codConcepto;
//	}
//
//	public void setCodConcepto(Long codConcepto) {
//		this.codConcepto = codConcepto;
//	}

	public Long getCodEvaluacion() {
		return codEvaluacion;
	}

	public void setCodEvaluacion(Long codEvaluacion) {
		this.codEvaluacion = codEvaluacion;
	}

	public Long getCodProyecto() {
		return codProyecto;
	}

	public void setCodProyecto(Long codProyecto) {
		this.codProyecto = codProyecto;
	}

	public String getDescComentario() {
		return descComentario;
	}

	public void setDescComentario(String descComentario) {
		this.descComentario = descComentario;
	}

	public String getRuta() {
		return ruta;
	}

	public void setRuta(String ruta) {
		this.ruta = ruta;
	}

	public float getCalificacion() {
		return calificacion;
	}

	public void setCalificacion(float calificacion) {
		this.calificacion = calificacion;
	}

	public Date getFecRegistro() {
		return fecRegistro;
	}

	public void setFecRegistro(Date fecRegistro) {
		this.fecRegistro = fecRegistro;
	}

	public Concepto getConcepto() {
		return concepto;
	}

	public void setConcepto(Concepto concepto) {
		this.concepto = concepto;
	}

	public Long getCodRecursoEvaluador() {
		return codRecursoEvaluador;
	}

	public void setCodRecursoEvaluador(Long codRecursoEvaluador) {
		this.codRecursoEvaluador = codRecursoEvaluador;
	}

//	public Evaluacion getEvaluacion() {
//		return evaluacion;
//	}
//
//	public void setEvaluacion(Evaluacion evaluacion) {
//		this.evaluacion = evaluacion;
//	}
//	
	

}
