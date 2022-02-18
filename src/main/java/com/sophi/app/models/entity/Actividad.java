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

import org.springframework.format.annotation.DateTimeFormat;

@Entity
@Table(name = "RECURSOS_ACTIVIDADES")
public class Actividad   implements Serializable {

	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_actividad")
	private Long codActividad;
	
	@Column(name = "desc_actividad_primaria")
	private String descActividadPrimaria;
	
	@Column(name = "desc_actividad_secundaria")
	private String descActividadSecundaria;
	
	@Column(name = "val_num_actividad")
	private Long valNumActividad;
	
	@Column(name = "fec_inicio_actividad")
	@Temporal(TemporalType.DATE)
	@DateTimeFormat(pattern = "dd/MM/yyyy")
	private Date fecInicioActividad;
	
	@Column(name = "fec_fin_actividad")
	@Temporal(TemporalType.DATE)
	@DateTimeFormat(pattern = "dd/MM/yyyy")
	private Date fecFinActividad;
	
	@Column(name = "cod_actividad_dependencia")
	private String codActividadDependiente;
	
	@Column(name = "val_duracion_actividad")
	private String valDuracionActividad;
	
	@Column(name = "val_nueva_actividad")
	private Long valNuevaActividad;
	
	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	@DateTimeFormat(pattern = "yyyy-MM-dd hh:mm:ss")
	private Date fecRegistro;
	
	@Column(name = "cod_recurso")
	private Long codRecurso;
	
	@Column(name = "desc_nombre_recurso")
	private String nombreRecurso;
	
	@Column(name = "cod_proyecto")
	private Long codProyecto;
	
	@Column(name = "cod_estatus_proyecto")
	private Long codEstatusProyecto;
	
	@Column(name = "cod_cliente")
	private Long codCliente;
	
	@Transient
	private String nombreProyecto;
	
	@PrePersist
	public void prePersist() {
		fecRegistro = new Date();
	}

	public Long getCodActividad() {
		return codActividad;
	}

	public void setCodActividad(Long codActividad) {
		this.codActividad = codActividad;
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

	public Long getValNumActividad() {
		return valNumActividad;
	}

	public void setValNumActividad(Long valNumActividad) {
		this.valNumActividad = valNumActividad;
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

	public String getCodActividadDependiente() {
		return codActividadDependiente;
	}

	public void setCodActividadDependiente(String codActividadDependiente) {
		this.codActividadDependiente = codActividadDependiente;
	}

	public String getValDuracionActividad() {
		return valDuracionActividad;
	}

	public void setValDuracionActividad(String valDuracionActividad) {
		this.valDuracionActividad = valDuracionActividad;
	}

	public Long getValNuevaActividad() {
		return valNuevaActividad;
	}

	public void setValNuevaActividad(Long valNuevaActividad) {
		this.valNuevaActividad = valNuevaActividad;
	}

	public Date getFecRegistro() {
		return fecRegistro;
	}

	public void setFecRegistro(Date fecRegistro) {
		this.fecRegistro = fecRegistro;
	}

	public Long getCodRecurso() {
		return codRecurso;
	}

	public void setCodRecurso(Long codRecurso) {
		this.codRecurso = codRecurso;
	}

	public String getNombreRecurso() {
		return nombreRecurso;
	}

	public void setNombreRecurso(String nombreRecurso) {
		this.nombreRecurso = nombreRecurso;
	}

	public Long getCodProyecto() {
		return codProyecto;
	}

	public void setCodProyecto(Long codProyecto) {
		this.codProyecto = codProyecto;
	}

	public Long getCodEstatusProyecto() {
		return codEstatusProyecto;
	}

	public void setCodEstatusProyecto(Long codEstatusProyecto) {
		this.codEstatusProyecto = codEstatusProyecto;
	}

	public Long getCodCliente() {
		return codCliente;
	}

	public void setCodCliente(Long codCliente) {
		this.codCliente = codCliente;
	}

	public String getNombreProyecto() {
		return nombreProyecto;
	}

	public void setNombreProyecto(String nombreProyecto) {
		this.nombreProyecto = nombreProyecto;
	}

	public Actividad() {
		
	}
	
	public Actividad(Long codActividad, String descActividadPrimaria, String descActividadSecundaria,
			Long valNumActividad, Date fecInicioActividad, Date fecFinActividad, String codActividadDependiente,
			String valDuracionActividad, Long valNuevaActividad, Date fecRegistro, Long codRecurso, Long codProyecto,
			Long codEstatusProyecto, Long codCliente) {
		super();
		this.codActividad = codActividad;
		this.descActividadPrimaria = descActividadPrimaria;
		this.descActividadSecundaria = descActividadSecundaria;
		this.valNumActividad = valNumActividad;
		this.fecInicioActividad = fecInicioActividad;
		this.fecFinActividad = fecFinActividad;
		this.codActividadDependiente = codActividadDependiente;
		this.valDuracionActividad = valDuracionActividad;
		this.valNuevaActividad = valNuevaActividad;
		this.fecRegistro = fecRegistro;
		this.codRecurso = codRecurso;
		this.codProyecto = codProyecto;
		this.codEstatusProyecto = codEstatusProyecto;
		this.codCliente = codCliente;
	}
	
	

}
