package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToMany;
import javax.persistence.Table;

@Entity
@Table(name = "CAT_TAREAS")
public class Tarea implements Serializable  {

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_tarea")
	private Long codTarea;
	
	@Column(name = "desc_tarea")
	private String descTarea;
	
	@OneToMany(fetch = FetchType.LAZY)
	@JoinColumn(name = "cod_tarea")
	private List<Subtarea> subtareas;

	public Long getCodTarea() {
		return codTarea;
	}

	public void setCodTarea(Long codTarea) {
		this.codTarea = codTarea;
	}

	public String getDescTarea() {
		return descTarea;
	}

	public void setDescTarea(String descTarea) {
		this.descTarea = descTarea;
	}

	public List<Subtarea> getSubtareas() {
		return subtareas;
	}

	public void setSubtareas(List<Subtarea> subtareas) {
		this.subtareas = subtareas;
	}
	
}
