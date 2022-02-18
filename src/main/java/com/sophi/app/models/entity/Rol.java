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

@Entity
@Table(name="ROLES")
public class Rol implements Serializable {
	
	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_rol")
	private Long codRol;
	
	@Column(name = "desc_rol")
	private String descRol;
	
	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	private Date fecRegistro;
	
	@Column(name = "cod_recurso")
	private Long cod_recurso;
	
	@Column(name = "cod_usuario")
	private Long cod_usuario;
	
	@PrePersist
	public void prePersist() {
		fecRegistro = new Date();
	}

	public Long getCodRol() {
		return codRol;
	}

	public void setCodRol(Long codRol) {
		this.codRol = codRol;
	}

	public String getDescRol() {
		return descRol;
	}

	public void setDescRol(String descRol) {
		this.descRol = descRol;
	}

	public Date getFecRegistro() {
		return fecRegistro;
	}

	public void setFecRegistro(Date fecRegistro) {
		this.fecRegistro = fecRegistro;
	}

	public Long getCod_recurso() {
		return cod_recurso;
	}

	public void setCod_recurso(Long cod_recurso) {
		this.cod_recurso = cod_recurso;
	}

	public Long getCod_usuario() {
		return cod_usuario;
	}

	public void setCod_usuario(Long cod_usuario) {
		this.cod_usuario = cod_usuario;
	}
	
}