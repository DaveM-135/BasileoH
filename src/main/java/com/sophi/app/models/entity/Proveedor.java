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
import javax.validation.constraints.NotEmpty;

import org.springframework.format.annotation.DateTimeFormat;

@Entity
@Table(name = "PROVEEDORES")
public class Proveedor implements Serializable{

	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_proveedor")
	private Long codProveedor;
	
	@NotEmpty(message = "Este dato no debe estar vacío")
	@Column(name = "desc_proveedor")
	private String descProveedor;
	
	@NotEmpty(message = "Este dato no debe estar vacío")
	@Column(name = "desc_tel_proveedor")
	private String descTelProveedor;
	
	@NotEmpty(message = "Este dato no debe estar vacío")
	@Column(name = "desc_direccion")
	private String descDireccion;
	
	@Column(name = "desc_comentario")
	private String descComentario;
	
	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	@DateTimeFormat(pattern = "yyyy-MM-dd hh:mm:ss")
	private Date fecRegistro;
	
	@Column(name = "val_activo")
	private Long valActivo;
	
	@PrePersist
	public void prePersist() {
		fecRegistro = new Date();
	}

	public Long getCodProveedor() {
		return codProveedor;
	}

	public void setCodProveedor(Long codProveedor) {
		this.codProveedor = codProveedor;
	}

	public String getDescProveedor() {
		return descProveedor;
	}

	public void setDescProveedor(String descProveedor) {
		this.descProveedor = descProveedor;
	}

	public String getDescTelProveedor() {
		return descTelProveedor;
	}

	public void setDescTelProveedor(String descTelProveedor) {
		this.descTelProveedor = descTelProveedor;
	}

	public String getDescDireccion() {
		return descDireccion;
	}

	public void setDescDireccion(String descDireccion) {
		this.descDireccion = descDireccion;
	}

	public String getDescComentario() {
		return descComentario;
	}

	public void setDescComentario(String descComentario) {
		this.descComentario = descComentario;
	}

	public Date getFecRegistro() {
		return fecRegistro;
	}

	public void setFecRegistro(Date fecRegistro) {
		this.fecRegistro = fecRegistro;
	}

	public Long getValActivo() {
		return valActivo;
	}

	public void setValActivo(Long valActivo) {
		this.valActivo = valActivo;
	}

	public static long getSerialversionuid() {
		return serialVersionUID;
	}

}