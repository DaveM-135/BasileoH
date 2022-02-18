package com.sophi.app.models.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "CAT_PARENTESCO")
public class Parentesco implements Serializable {

	private static final long serialVersionUID = 1L;

	@Id
	@Column(name = "cod_parentesco")
	private Long codParentesco;

	@Column(name = "desc_parentesco")
	private String descParentesco;

	public Long getCodParentesco() {
		return codParentesco;
	}

	public void setCodParentesco(Long codParentesco) {
		this.codParentesco = codParentesco;
	}

	public String getDescParentesco() {
		return descParentesco;
	}

	public void setDescParentesco(String descParentesco) {
		this.descParentesco = descParentesco;
	}
	
	

}
