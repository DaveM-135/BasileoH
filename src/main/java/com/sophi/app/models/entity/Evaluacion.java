package com.sophi.app.models.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "CAT_EVALUACION")
public class Evaluacion implements Serializable {

	private static final long serialVersionUID = 1L;
	
	@Id
	@Column(name = "cod_evaluacion")
	private Long codEvaluacion; 
	
	@Column(name = "desc_evaluacion")
	private String descEvaluacion;
	
	@Column(name = "val_ponderacion")
	private float valPonderacion;

	public Long getCodEvaluacion() {
		return codEvaluacion;
	}

	public void setCodEvaluacion(Long codEvaluacion) {
		this.codEvaluacion = codEvaluacion;
	}

	public String getDescEvaluacion() {
		return descEvaluacion;
	}

	public void setDescEvaluacion(String descEvaluacion) {
		this.descEvaluacion = descEvaluacion;
	}

	public float getValPonderacion() {
		return valPonderacion;
	}

	public void setValPonderacion(float valPonderacion) {
		this.valPonderacion = valPonderacion;
	}
	
	
	
	

}
