package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.Objects;

import javax.persistence.Column;
import javax.persistence.Embeddable;

@Embeddable
public class RecursoCapacitacionId implements Serializable {

	private static final long serialVersionUID = 1L;
	
	@Column(name = "cod_capacitacion")
	private Long codCapacitacion;
	
	@Column(name = "cod_recurso")
	private Long codRecurso;
	
	public RecursoCapacitacionId() {
		
	}
	
	public RecursoCapacitacionId(Long codCapacitacion, Long codRecurso) {
		super();
		this.codCapacitacion = codCapacitacion;
		this.codRecurso = codRecurso;
	}
	
	@Override
	public int hashCode() {
		return Objects.hash(codCapacitacion, codRecurso);
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RecursoCapacitacionId recursocapacitacionId = (RecursoCapacitacionId) o;
        return codCapacitacion.equals(recursocapacitacionId.codCapacitacion) &&
        		codRecurso.equals(recursocapacitacionId.codRecurso);
	}

	public Long getCodCapacitacion() {
		return codCapacitacion;
	}

	public void setCodCapacitacion(Long codCapacitacion) {
		this.codCapacitacion = codCapacitacion;
	}

	public Long getCodRecurso() {
		return codRecurso;
	}

	public void setCodRecurso(Long codRecurso) {
		this.codRecurso = codRecurso;
	}

	public static long getSerialversionuid() {
		return serialVersionUID;
	}
}
