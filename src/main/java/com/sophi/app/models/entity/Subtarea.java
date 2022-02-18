package com.sophi.app.models.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import javax.persistence.Table;

@Entity
@Table(name = "CAT_SUBTAREAS")
public class Subtarea implements Serializable  {

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_subtarea")
	private Long codSubtarea;
	
	@Column(name = "desc_subtarea")
	private String descSubtarea;
	
	@OneToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "cod_tarea")
	private Tarea tarea;

	public Long getCodSubtarea() {
		return codSubtarea;
	}

	public void setCodSubtarea(Long codSubtarea) {
		this.codSubtarea = codSubtarea;
	}

	public String getDescSubtarea() {
		return descSubtarea;
	}

	public void setDescSubTarea(String descSubtarea) {
		this.descSubtarea = descSubtarea;
	}

	public Tarea getTarea() {
		return tarea;
	}

	public void setTarea(Tarea tarea) {
		this.tarea = tarea;
	}
	
}
