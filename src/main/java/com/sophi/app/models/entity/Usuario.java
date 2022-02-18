package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToMany;
import javax.persistence.PrePersist;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

@Entity
@Table(name="USUARIOS")
public class Usuario implements Serializable {

	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_usuario")
	private Long codUsuario;
	
	@Column(name = "desc_nombre_usuario")
	private String descNombreUsuario;
	
	@Column(name = "desc_contrasena")
	private String descContrasena;
	
	@Column(name = "desc_activo")
	private Boolean descActivo;
	
	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	private Date fecRegistro;
	
	@Column(name = "desc_usuario")
	private String descUsuario;
	
	@Column(name = "cod_recurso")
	private Long cod_recurso;
	
	@OneToMany(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
	@JoinColumn(name = "cod_usuario")
	private List<Rol> roles;
	
	@PrePersist
	public void prePersist() {
		fecRegistro = new Date();
	}

	public Long getCodUsuario() {
		return codUsuario;
	}

	public void setCodUsuario(Long codUsuario) {
		this.codUsuario = codUsuario;
	}

	public String getDescNombreUsuario() {
		return descNombreUsuario;
	}

	public void setDescNombreUsuario(String descNombreUsuario) {
		this.descNombreUsuario = descNombreUsuario;
	}

	public String getDescContrasena() {
		return descContrasena;
	}

	public void setDescContrasena(String descContrasena) {
		this.descContrasena = descContrasena;
	}

	public Boolean getDescActivo() {
		return descActivo;
	}

	public void setDescActivo(Boolean descActivo) {
		this.descActivo = descActivo;
	}

	public Date getFecRegistro() {
		return fecRegistro;
	}

	public void setFecRegistro(Date fecRegistro) {
		this.fecRegistro = fecRegistro;
	}

	public String getDescUsuario() {
		return descUsuario;
	}

	public void setDescUsuario(String descUsuario) {
		this.descUsuario = descUsuario;
	}

	public Long getCod_recurso() {
		return cod_recurso;
	}

	public void setCod_recurso(Long cod_recurso) {
		this.cod_recurso = cod_recurso;
	}

	public List<Rol> getRoles() {
		return roles;
	}

	public void setRoles(List<Rol> roles) {
		this.roles = roles;
	}

	

}