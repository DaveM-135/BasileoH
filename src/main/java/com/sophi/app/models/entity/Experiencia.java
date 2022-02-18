package com.sophi.app.models.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "CAT_NIVEL_EXPERIENCIA")
public class Experiencia implements Serializable {

	private static final long serialVersionUID = 1L;
	
	@Id
	@Column(name = "cod_nivel_experiencia")
	private Long codNivelExperiencia;
	
	@Column(name = "desc_nivel_experiencia")
	private String descNivelExperiencia;

	public Long getCodNivelExperiencia() {
		return codNivelExperiencia;
	}

	public void setCodNivelExperiencia(Long codNivelExperiencia) {
		this.codNivelExperiencia = codNivelExperiencia;
	}

	public String getDescNivelExperiencia() {
		return descNivelExperiencia;
	}

	public void setDescNivelExperiencia(String descNivelExperiencia) {
		this.descNivelExperiencia = descNivelExperiencia;
	}

}
