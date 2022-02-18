package com.sophi.app.models.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name="CAT_GRADO_ESCOLARIDAD")
public class GradoEscolar implements Serializable {
	
	private static final long serialVersionUID = 1L;
	
	@Id
	@Column(name = "cod_grado_escolar")
	private	Long codGradoEscolaridad;
	
	@Column(name = "desc_grado_escolar")
	private String descGradoEscolaridad;

	public Long getCodGradoEscolaridad() {
		return codGradoEscolaridad;
	}

	public void setCodGradoEscolaridad(Long codGradoEscolaridad) {
		this.codGradoEscolaridad = codGradoEscolaridad;
	}

	public String getDescGradoEscolaridad() {
		return descGradoEscolaridad;
	}

	public void setDescGradoEscolaridad(String descGradoEscolaridad) {
		this.descGradoEscolaridad = descGradoEscolaridad;
	}

	
}
