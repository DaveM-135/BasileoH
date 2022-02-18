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
import javax.validation.constraints.NotEmpty;

import org.springframework.format.annotation.DateTimeFormat;

@Entity
@Table(name = "RECURSOS_HERRAMIENTAS")
public class Infraestructura   implements Serializable{

	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_infraestructura")
	private Long codInfraestructura;
	
	@NotEmpty(message = "Este dato no debe estar vacío")
	@Column(name = "desc_infraestructura")
	private String descInfraestructura;
	
	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	@DateTimeFormat(pattern = "yyyy-MM-dd hh:mm:ss")
	private Date fecRegistro;
	
	@PrePersist
	public void prePersist() {
		fecRegistro = new Date();
	}

	public Long getCodInfraestructura() {
		return codInfraestructura;
	}

	public void setCodInfraestructura(Long codInfraestructura) {
		this.codInfraestructura = codInfraestructura;
	}

	public String getDescInfraestructura() {
		return descInfraestructura;
	}

	public void setDescInfraestructura(String descInfraestructura) {
		this.descInfraestructura = descInfraestructura;
	}

	public Date getFecRegistro() {
		return fecRegistro;
	}

	public void setFecRegistro(Date fecRegistro) {
		this.fecRegistro = fecRegistro;
	}

	public static long getSerialversionuid() {
		return serialVersionUID;
	}
	
	

}
