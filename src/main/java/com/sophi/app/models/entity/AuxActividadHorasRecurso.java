package com.sophi.app.models.entity;

import java.util.Date;

public class AuxActividadHorasRecurso {
	
	private Long idProyecto;
	private String descProyecto;
	private Long idActividad;
	private String descActividad;
	private Long idCapHora;
	private String descComentario;
	private Date fechaActividad;
	private Date fechaValidada;
	private Float horasCapturadas;
	private Float horasPlaneadas;
	private Float horasAprobadas;
	private Long valRechazo;
	private int dia;
	
	public Float getHorasAprobadas() {
		return horasAprobadas;
	}
	public void setHorasAprobadas(Float horasAprobadas) {
		this.horasAprobadas = horasAprobadas;
	}
	public Float getHorasPlaneadas() {
		return horasPlaneadas;
	}
	public void setHorasPlaneadas(Float horasPlaneadas) {
		this.horasPlaneadas = horasPlaneadas;
	}
	public Date getFechaValidada() {
		return fechaValidada;
	}
	public void setFechaValidada(Date fechaValidada) {
		this.fechaValidada = fechaValidada;
	}
	public int getDia() {
		return dia;
	}
	public void setDia(int dia) {
		this.dia = dia;
	}
	public Long getIdProyecto() {
		return idProyecto;
	}
	public void setIdProyecto(Long idProyecto) {
		this.idProyecto = idProyecto;
	}
	public String getDescProyecto() {
		return descProyecto;
	}
	public void setDescProyecto(String descProyecto) {
		this.descProyecto = descProyecto;
	}
	public Long getIdActividad() {
		return idActividad;
	}
	public void setIdActividad(Long idActividad) {
		this.idActividad = idActividad;
	}
	public String getDescActividad() {
		return descActividad;
	}
	public void setDescActividad(String descActividad) {
		this.descActividad = descActividad;
	}
	public Long getIdCapHora() {
		return idCapHora;
	}
	public void setIdCapHora(Long idCapHora) {
		this.idCapHora = idCapHora;
	}
	public String getDescComentario() {
		return descComentario;
	}
	public void setDescComentario(String descComentario) {
		this.descComentario = descComentario;
	}
	public Date getFechaActividad() {
		return fechaActividad;
	}
	public void setFechaActividad(Date fechaActividad) {
		this.fechaActividad = fechaActividad;
	}
	public Float getHorasCapturadas() {
		return horasCapturadas;
	}
	public void setHorasCapturadas(Float horasCapturadas) {
		this.horasCapturadas = horasCapturadas;
	}
	public Long getValRechazo() {
		return valRechazo;
	}
	public void setValRechazo(Long valRechazo) {
		this.valRechazo = valRechazo;
	}
	

}
