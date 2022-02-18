package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.persistence.Transient;

import org.springframework.format.annotation.DateTimeFormat;

@Entity
@Table(name = "CAT_CAPACITACIONES")
public class Capacitaciones implements Serializable {

	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_capacitacion")
	private Long codCapacitacion;
	
	@Column(name = "desc_capacitacion")
	private String descCapacitacion;
	
	@Column(name = "desc_detalle_capacitacion")
	private String descDetalleCapacitacion;
	
	@Column(name = "val_hrs_capacitacion")
	private Long valHrsCapacitacion;
	
	@Column(name = "desc_ubicacion_enlace")
	private String descUbicacionEnlace;
	
	@Column(name = "desc_proveedor")
	private String descProveedor;
	
	@Column(name = "desc_categoria")
	private String descCategoria;
	
	@Column(name = "desc_solicitado")
	private String descSolicitado;
	
	@Transient
	private Long valBorrar;
	
	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date fecRegistro;

	public Long getCodCapacitacion() {
		return codCapacitacion;
	}

	public void setCodCapacitacion(Long codCapacitacion) {
		this.codCapacitacion = codCapacitacion;
	}

	public String getDescCapacitacion() {
		return descCapacitacion;
	}

	public void setDescCapacitacion(String descCapacitacion) {
		this.descCapacitacion = descCapacitacion;
	}

	public String getDescDetalleCapacitacion() {
		return descDetalleCapacitacion;
	}

	public void setDescDetalleCapacitacion(String descDetalleCapacitacion) {
		this.descDetalleCapacitacion = descDetalleCapacitacion;
	}

	public Long getValHrsCapacitacion() {
		return valHrsCapacitacion;
	}

	public void setValHrsCapacitacion(Long valHrsCapacitacion) {
		this.valHrsCapacitacion = valHrsCapacitacion;
	}

	public String getDescUbicacionEnlace() {
		return descUbicacionEnlace;
	}

	public void setDescUbicacionEnlace(String descUbicacionEnlace) {
		this.descUbicacionEnlace = descUbicacionEnlace;
	}

	public String getDescProveedor() {
		return descProveedor;
	}

	public void setDescProveedor(String descProveedor) {
		this.descProveedor = descProveedor;
	}

	public String getDescCategoria() {
		return descCategoria;
	}

	public void setDescCategoria(String descCategoria) {
		this.descCategoria = descCategoria;
	}


	public Date getFecRegistro() {
		return fecRegistro;
	}

	public void setFecRegistro(Date fecRegistro) {
		this.fecRegistro = fecRegistro;
	}

	public String getDescSolicitado() {
		return descSolicitado;
	}

	public void setDescSolicitado(String descSolicitado) {
		this.descSolicitado = descSolicitado;
	}

	public Long getValBorrar() {
		return valBorrar;
	}

	public void setValBorrar(Long valBorrar) {
		this.valBorrar = valBorrar;
	}
 	
}
