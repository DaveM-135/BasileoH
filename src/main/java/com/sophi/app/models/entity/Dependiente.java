package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.PrePersist;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.validation.constraints.NotEmpty;

import org.springframework.format.annotation.DateTimeFormat;

@Entity
@Table(name = "RECURSOS_DEPENDIENTES")
public class Dependiente  implements Serializable {

	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_dependiente")
	private Long codDependiente;
	
	@NotEmpty(message = "Este dato no debe estar vacío")
	@Column(name = "desc_dependiente")
	private String descDependiente;
	
	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	@DateTimeFormat(pattern = "yyyy-MM-dd hh:mm:ss")
	private Date fecRegistro;
	
	@PrePersist
	public void prePersist() {
		fecRegistro = new Date();
	}
	
	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "cod_recurso")
	private Recurso recurso;

	public Long getCodDependiente() {
		return codDependiente;
	}

	public void setCodDependiente(Long codDependiente) {
		this.codDependiente = codDependiente;
	}

	public String getDescDependiente() {
		return descDependiente;
	}

	public void setDescDependiente(String descDependiente) {
		this.descDependiente = descDependiente;
	}

	public Date getFecRegistro() {
		return fecRegistro;
	}

	public void setFecRegistro(Date fecRegistro) {
		this.fecRegistro = fecRegistro;
	}

	public Recurso getRecurso() {
		return recurso;
	}

	public void setRecurso(Recurso recurso) {
		this.recurso = recurso;
	}

	public static long getSerialversionuid() {
		return serialVersionUID;
	}

	
}
