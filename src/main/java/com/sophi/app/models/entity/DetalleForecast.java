package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import javax.persistence.PrePersist;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

import org.springframework.format.annotation.DateTimeFormat;

@Entity
@Table(name = "DETALLE_FORECAST")
public class DetalleForecast implements Serializable  {

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_forecast")
	private Long codForecast;
	
	@OneToOne
	@JoinColumn(name = "cod_recurso", insertable = true, updatable = true)
	private Recurso recurso;
	
	@OneToOne
	@JoinColumn(name = "cod_proyecto", insertable = true, updatable = true)
	private Proyecto proyecto;
	
	@OneToOne
	@JoinColumn(name = "cod_clasificacion", insertable = true, updatable = true)
	private ClasificacionForecast clasificacionForecast;
	
	@OneToOne
	@JoinColumn(name = "cod_mes", insertable = true, updatable = true)
	private MesHabil mesHabil;
	
	@Column(name = "val_horas")
	private Float valHoras;
	
	@Column(name = "fec_inicio_actividad")
	@Temporal(TemporalType.DATE)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date fecInicioActividad;
	
	@Column(name = "fec_fin_actividad")
	@Temporal(TemporalType.DATE)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date fecFinActividad;
	
	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	@DateTimeFormat(pattern = "yyyy-MM-dd hh:mm:ss")
	private Date fecRegistro;
	
	@PrePersist
	public void prePersist() {
		fecRegistro = new Date();
	}

	public Long getCodForecast() {
		return codForecast;
	}

	public void setCodForecast(Long codForecast) {
		this.codForecast = codForecast;
	}

	public Recurso getRecurso() {
		return recurso;
	}

	public void setRecurso(Recurso recurso) {
		this.recurso = recurso;
	}

	public ClasificacionForecast getClasificacionForecast() {
		return clasificacionForecast;
	}

	public void setClasificacionForecast(ClasificacionForecast clasificacionForecast) {
		this.clasificacionForecast = clasificacionForecast;
	}

	public MesHabil getMesHabil() {
		return mesHabil;
	}

	public void setMesHabil(MesHabil mesHabil) {
		this.mesHabil = mesHabil;
	}

	public Float getValHoras() {
		return valHoras;
	}

	public void setValHoras(Float valHoras) {
		this.valHoras = valHoras;
	}

	public Date getFecInicioActividad() {
		return fecInicioActividad;
	}

	public void setFecInicioActividad(Date fecInicioActividad) {
		this.fecInicioActividad = fecInicioActividad;
	}

	public Date getFecFinActividad() {
		return fecFinActividad;
	}

	public void setFecFinActividad(Date fecFinActividad) {
		this.fecFinActividad = fecFinActividad;
	}

	public Date getFecRegistro() {
		return fecRegistro;
	}

	public void setFecRegistro(Date fecRegistro) {
		this.fecRegistro = fecRegistro;
	}

	public Proyecto getProyecto() {
		return proyecto;
	}

	public void setProyecto(Proyecto proyecto) {
		this.proyecto = proyecto;
	}
	
	
	

}
