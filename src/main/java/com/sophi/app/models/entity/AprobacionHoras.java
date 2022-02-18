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
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.persistence.Transient;

import org.hibernate.validator.constraints.Range;
import org.springframework.format.annotation.DateTimeFormat;

@Entity
@Table(name = "RECURSOS_CAP_HORAS")
public class AprobacionHoras implements Serializable {
	
	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_cap_hora")
	private Long codCapHora;
	
	@Column(name = "cod_actividad")
	private Long codActividad;
	
	@Column(name = "cod_recurso")
	private Long codRecurso;
	
	@Column(name = "cod_cliente")
	private Long codCliente;
	
	@Column(name = "cod_estatus_proyecto")
	private Long codEstatusProyecto;

//	@OneToOne
//	@JoinColumn(name = "cod_actividad", insertable = false, updatable = false)
//	private Actividad actividad;
	
	@OneToOne
	@JoinColumn(name = "cod_recurso", insertable = false, updatable = false)
	private Recurso recurso;
	
	@Column(name = "cod_proyecto", insertable = false, updatable = false)
	private Long codProyecto;

	@Column(name = "desc_comentario_detalle")
	private String descComentarioDetalle;
	
	@Column(name = "fec_inicio_actividad")
	@Temporal(TemporalType.DATE)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date fecInicioActividad;
	
	@Column(name = "fec_fin_actividad")
	@Temporal(TemporalType.TIMESTAMP)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date fecFinActividad;
	
	@Column(name = "fec_registro")
	@Temporal(TemporalType.DATE)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date fecRegistro;

	@Column(name = "val_duracion_reportada")
	private Float valDuracionReportada;
	
	@Range(min=0, max=24, message="No puedes capturar más de 24 horas")
	@Column(name = "val_duracion_validada")
	private Float valDuracionValidada;
	
	@Column(name = "cod_recurso_validador")
	private Long codRecursoValidador;
	
	@Column(name = "fec_validacion")
	@Temporal(TemporalType.DATE)
	@DateTimeFormat(pattern = "yyyy-MM-dd") 
	private Date fecValidacion;
	
	@Column(name = "val_nueva_actividad")
	private Long valNuevaActividad;
	
	@Transient
	private Float horasPlaneadas;
	
	@Transient
	private String descProyecto;
	
	@Transient
	private String descActividadSecundaria;
	
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

	public Long getCodProyecto() {
		return codProyecto;
	}

	public void setCodProyecto(Long codProyecto) {
		this.codProyecto = codProyecto;
	}

//	public Actividad getActividad() {
//		return actividad;
//	}
//
//	public void setActividad(Actividad actividad) {
//		this.actividad = actividad;
//	}
	
	public Recurso getRecurso() {
		return recurso;
	}

	public void setRecurso(Recurso recurso) {
		this.recurso = recurso;
	}
	
	public String getDescComentarioDetalle() {
		return descComentarioDetalle;
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

	public Date getFecRegistro() {
		return fecRegistro;
	}

	public void setFecRegistro(Date fecRegistro) {
		this.fecRegistro = fecRegistro;
	}

	public Float getValDuracionReportada() {
		return valDuracionReportada;
	}

	public void setValDuracionReportada(Float valDuracionReportada) {
		this.valDuracionReportada = valDuracionReportada;
	}

	public Float getValDuracionValidada() {
		return valDuracionValidada;
	}

	public void setValDuracionValidada(Float valDuracionValidada) {
		this.valDuracionValidada = valDuracionValidada;
	}

	public Long getCodRecursoValidador() {
		return codRecursoValidador;
	}

	public void setCodRecursoValidador(Long codRecursoValidador) {
		this.codRecursoValidador = codRecursoValidador;
	}

	public Date getFecValidacion() {
		return fecValidacion;
	}

	public void setFecValidacion(Date fecValidacion) {
		this.fecValidacion = fecValidacion;
	}

	public Long getValNuevaActividad() {
		return valNuevaActividad;
	}

	public void setValNuevaActividad(Long valNuevaActividad) {
		this.valNuevaActividad = valNuevaActividad;
	}
	
	public Float getHorasPlaneadas() {
		return horasPlaneadas;
	}

	public void setHorasPlaneadas(Float horasPlaneadas) {
		this.horasPlaneadas = horasPlaneadas;
	}

	public String getDescProyecto() {
		return descProyecto;
	}

	public void setDescProyecto(String descProyecto) {
		this.descProyecto = descProyecto;
	}

	public String getDescActividadSecundaria() {
		return descActividadSecundaria;
	}

	public void setDescActividadSecundaria(String descActividadSecundaria) {
		this.descActividadSecundaria = descActividadSecundaria;
	}

	public static long getSerialversionuid() {
		return serialVersionUID;
	}

}
