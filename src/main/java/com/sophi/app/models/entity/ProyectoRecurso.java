package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.persistence.Transient;

import org.springframework.format.annotation.DateTimeFormat;

@Entity
@Table(name = "PROYECTOS_RECURSOS")
public class ProyectoRecurso implements Serializable{

	private static final long serialVersionUID = 1L;
	
	@EmbeddedId
	ProyectoRecursoId proyectoRecursoId;
	
	@Column(name = "fec_inicio_asignacion")
	@Temporal(TemporalType.DATE)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date fecInicioAsignacion;
	
	@Column(name = "fec_fin_asignacion")
	@Temporal(TemporalType.DATE)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date fecFinAsignacion;
	
	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	@DateTimeFormat(pattern = "yyyy-MM-dd hh:mm:ss")
	private Date fecRegistro;
	
	@Column(name = "imp_costo_recurso")
	private float impCostoRecurso;
	
	@Column(name = "val_horas_recurso")
	private Float valHorasRecurso;
	
	@Transient
	private String nombreRecurso;
	
	public String getNombreRecurso() {
		return nombreRecurso;
	}

	public void setNombreRecurso(String nombreRecurso) {
		this.nombreRecurso = nombreRecurso;
	}

	public ProyectoRecursoId getProyectoRecursoId() {
		return proyectoRecursoId;
	}

	public void setProyectoRecursoId(ProyectoRecursoId proyectoRecursoId) {
		this.proyectoRecursoId = proyectoRecursoId;
	}

	public Date getFecInicioAsignacion() {
		return fecInicioAsignacion;
	}

	public void setFecInicioAsignacion(Date fecInicioAsignacion) {
		this.fecInicioAsignacion = fecInicioAsignacion;
	}

	public Date getFecFinAsignacion() {
		return fecFinAsignacion;
	}

	public void setFecFinAsignacion(Date fecFinAsignacion) {
		this.fecFinAsignacion = fecFinAsignacion;
	}

	public Date getFecRegistro() {
		return fecRegistro;
	}

	public void setFecRegistro(Date fecRegistro) {
		this.fecRegistro = fecRegistro;
	}

	public float getImpCostoRecurso() {
		return impCostoRecurso;
	}

	public void setImpCostoRecurso(float impCostoRecurso) {
		this.impCostoRecurso = impCostoRecurso;
	}

	public Float getValHorasRecurso() {
		return valHorasRecurso;
	}

	public void setValHorasRecurso(Float valHorasRecurso) {
		this.valHorasRecurso = valHorasRecurso;
	}

	public static long getSerialversionuid() {
		return serialVersionUID;
	}

	public ProyectoRecurso(ProyectoRecursoId id, Date fecInicioAsignacion, Date  fecFinAsignacion,
			Date fecRegistro, float impCostoRecurso, Float valHorasRecurso
			) {
		super();
		proyectoRecursoId = id;
		this.fecInicioAsignacion = fecInicioAsignacion;
		this.fecFinAsignacion = fecFinAsignacion;
		this.fecRegistro = fecRegistro;
		this.impCostoRecurso = impCostoRecurso;
		this.valHorasRecurso = valHorasRecurso;
	}

	public ProyectoRecurso() {
		
	}
	
	
	
}
