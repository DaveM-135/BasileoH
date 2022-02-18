package com.sophi.app.models.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import javax.persistence.Table;


@Entity
@Table(name="RECURSOS_ESCOLARIDAD")
public class RecursoEscolaridad implements Serializable {
	
private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_recurso_escolaridad")
	private Long codRecursoEscolaridad;
	
	@Column(name = "cod_recurso")
	private Long codRecurso;
	
	@Column(name = "desc_institucion_academica")
	private String descInstitucionAcademica;
	
	@Column(name = "desc_carrera")
	private String descCarrera;
	
	@Column(name = "desc_cedula_profesional")
	private String descCedulaProfesional;
	
	@Column(name = "fec_inicio")
	private String fecInicio;
	
	@Column(name = "fec_fin")
	private String fecFin;
	
	@Column(name = "cod_grado_escolar")
	private Long codGradoEscolar;
	
	@Column(name = "cod_etapa_escolar")
	private Long codEtapaEscolar;
	
	@OneToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "cod_grado_escolar",insertable = false, updatable = false)
	private GradoEscolar gradoEscolar ;
	
	@OneToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "cod_etapa_escolar",insertable = false, updatable = false)
	private EtapaEscolar etapaEscolar;

	public Long getCodRecursoEscolaridad() {
		return codRecursoEscolaridad;
	}

	public void setCodRecursoEscolaridad(Long codRecursoEscolaridad) {
		this.codRecursoEscolaridad = codRecursoEscolaridad;
	}

	public Long getCodRecurso() {
		return codRecurso;
	}

	public void setCodRecurso(Long codRecurso) {
		this.codRecurso = codRecurso;
	}

	public String getDescInstitucionAcademica() {
		return descInstitucionAcademica;
	}

	public void setDescInstitucionAcademica(String descInstitucionAcademica) {
		this.descInstitucionAcademica = descInstitucionAcademica;
	}

	public String getDescCedulaProfesional() {
		return descCedulaProfesional;
	}

	public void setDescCedulaProfesional(String descCedulaProfesional) {
		this.descCedulaProfesional = descCedulaProfesional;
	}

	public Long getCodGradoEscolar() {
		return codGradoEscolar;
	}

	public void setCodGradoEscolar(Long codGradoEscolar) {
		this.codGradoEscolar = codGradoEscolar;
	}

	public Long getCodEtapaEscolar() {
		return codEtapaEscolar;
	}

	public void setCodEtapaEscolar(Long codEtapaEscolar) {
		this.codEtapaEscolar = codEtapaEscolar;
	}

	public static long getSerialversionuid() {
		return serialVersionUID;
	}

	public GradoEscolar getGradoEscolar() {
		return gradoEscolar;
	}

	public void setGradoEscolar(GradoEscolar gradoEscolar) {
		this.gradoEscolar = gradoEscolar;
	}

	public EtapaEscolar getEtapaEscolar() {
		return etapaEscolar;
	}

	public void setEtapaEscolar(EtapaEscolar etapaEscolar) {
		this.etapaEscolar = etapaEscolar;
	}

	public String getDescCarrera() {
		return descCarrera;
	}

	public void setDescCarrera(String descCarrera) {
		this.descCarrera = descCarrera;
	}

	public String getFecInicio() {
		return fecInicio;
	}

	public void setFecInicio(String fecInicio) {
		this.fecInicio = fecInicio;
	}

	public String getFecFin() {
		return fecFin;
	}

	public void setFecFin(String fecFin) {
		this.fecFin = fecFin;
	}
	
	
}
