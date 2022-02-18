package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.PrePersist;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.persistence.Transient;
import javax.validation.constraints.NotEmpty;

import org.hibernate.validator.constraints.Range;
import org.springframework.format.annotation.DateTimeFormat;

@Entity
@Table(name = "RECURSOS_CAP_HORAS")
public class CapHora implements Serializable{

	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_cap_hora")
	private Long codCapHora;
	
	@Column(name = "cod_actividad")
	private Long codActividad;
	
	@Column(name = "cod_recurso")
	private Long codRecurso;
	
	@Column(name = "cod_proyecto")
	private Long codProyecto;
	
	@Column(name = "cod_cliente")
	private Long codCliente;
	
	@Column(name = "cod_estatus_proyecto")
	private Long codEstatusProyecto;
	
	@Column(name = "val_rechazo")
	private Long valRechazo;
	
	@NotEmpty(message = "Este dato no debe estar vacío")
	@Column(name = "desc_comentario_detalle")
	private String descComentarioDetalle;
	
	@Transient
	private String descActividadPrimaria;
	
	@Transient
	private String descActividadSecundaria;
	
	@Transient
	private String descProyecto;
	
	@Transient
	private Float horasPlaneadas;
	
	@Column(name = "fec_inicio_actividad")
	@Temporal(TemporalType.DATE)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date fecInicioActividad;
	
	@Column(name = "fec_fin_actividad")
	@Temporal(TemporalType.DATE)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date fecFinActividad;
	
	@Range(min=0, max=24, message="No puedes capturar más de 24 horas")
	@Column(name = "val_duracion_reportada")
	private float valDuracionReportada;

	@Column(name = "val_duracion_validada")
	private float valDuracionValidad;
	
	@Column(name = "val_duracion_rechazada")
	private float valDuracionRechazada;
	
	@Column(name = "cod_recurso_validador")
	private Long codRecursoValidador;
	
	@Column(name = "val_nueva_actividad")
	private Long valNuevaActividad;
	
	@Column(name = "fec_validacion")
	@Temporal(TemporalType.DATE)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date fecValidacion;

	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	@DateTimeFormat(pattern = "yyyy-MM-dd hh:mm:ss")
	private Date fecRegistro;
	
	@Column(name = "desc_rechazo")
	private String descRechazo;
	
	@PrePersist
	public void prePersist() {
		fecRegistro = new Date();
	}

	public Long getValRechazo() {
		return valRechazo;
	}

	public void setValRechazo(Long valRechazo) {
		this.valRechazo = valRechazo;
	}

	public String getDescComentarioDetalle() {
		return descComentarioDetalle;
	}

	public Long getCodCapHora() {
		return codCapHora;
	}

	public void setCodCapHora(Long codCapHora) {
		this.codCapHora = codCapHora;
	}

	public Long getCodActividad() {
		return codActividad;
	}

	public void setCodActividad(Long codActividad) {
		this.codActividad = codActividad;
	}

	public Long getCodRecurso() {
		return codRecurso;
	}

	public void setCodRecurso(Long codRecurso) {
		this.codRecurso = codRecurso;
	}

	public Long getCodProyecto() {
		return codProyecto;
	}

	public void setCodProyecto(Long codProyecto) {
		this.codProyecto = codProyecto;
	}

	public Long getCodCliente() {
		return codCliente;
	}

	public void setCodCliente(Long codCliente) {
		this.codCliente = codCliente;
	}

	public Long getCodEstatusProyecto() {
		return codEstatusProyecto;
	}

	public void setCodEstatusProyecto(Long codEstatusProyecto) {
		this.codEstatusProyecto = codEstatusProyecto;
	}

	public void setDescComentarioDetalle(String descComentarioDetalle) {
		this.descComentarioDetalle = descComentarioDetalle;
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

	public float getValDuracionReportada() {
		return valDuracionReportada;
	}

	public void setValDuracionReportada(float valDuracionReportada) {
		this.valDuracionReportada = valDuracionReportada;
	}

	public float getValDuracionValidad() {
		return valDuracionValidad;
	}

	public void setValDuracionValidad(float valDuracionValidad) {
		this.valDuracionValidad = valDuracionValidad;
	}

	public Long getCodRecursoValidador() {
		return codRecursoValidador;
	}

	public void setCodRecursoValidador(Long codRecursoValidador) {
		this.codRecursoValidador = codRecursoValidador;
	}

	public Long getValNuevaActividad() {
		return valNuevaActividad;
	}

	public void setValNuevaActividad(Long valNuevaActividad) {
		this.valNuevaActividad = valNuevaActividad;
	}

	public Date getFecValidacion() {
		return fecValidacion;
	}

	public void setFecValidacion(Date fecValidacion) {
		this.fecValidacion = fecValidacion;
	}

	public Date getFecRegistro() {
		return fecRegistro;
	}

	public void setFecRegistro(Date fecRegistro) {
		this.fecRegistro = fecRegistro;
	}

	public static long getSerialversionuid() {
		return serialVersionUID;
	}
	
	public String getDescActividadPrimaria() {
		return descActividadPrimaria;
	}

	public void setDescActividadPrimaria(String descActividadPrimaria) {
		this.descActividadPrimaria = descActividadPrimaria;
	}
	
	public String getDescActividadSecundaria() {
		return descActividadSecundaria;
	}

	public void setDescActividadSecundaria(String descActividadSecundaria) {
		this.descActividadSecundaria = descActividadSecundaria;
	}
	
	public String getDescProyecto() {
		return descProyecto;
	}

	public void setDescProyecto(String descProyecto) {
		this.descProyecto = descProyecto;
	}

	public Float getHorasPlaneadas() {
		return horasPlaneadas;
	}

	public void setHorasPlaneadas(Float horasPlaneadas) {
		this.horasPlaneadas = horasPlaneadas;
	}

	public float getValDuracionRechazada() {
		return valDuracionRechazada;
	}

	public void setValDuracionRechazada(float valDuracionRechazada) {
		this.valDuracionRechazada = valDuracionRechazada;
	}

	public String getDescRechazo() {
		return descRechazo;
	}

	public void setDescRechazo(String descRechazo) {
		this.descRechazo = descRechazo;
	}
	
	

}
