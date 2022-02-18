package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

@Entity
@Table(name = "CAT_JORNADA")
public class Jornada implements Serializable {
	
	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_jornada")
	private Long codJornada;
	
	@Column(name = "desc_jornada")
	private String descJornada;
	
	@Column(name = "val_horas_semana")
	private String valHorasSemana;

	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	private Date fecRegistro;

	public Long getCodJornada() {
		return codJornada;
	}

	public void setCodJornada(Long codJornada) {
		this.codJornada = codJornada;
	}

	public String getDescJornada() {
		return descJornada;
	}

	public void setDescJornada(String descJornada) {
		this.descJornada = descJornada;
	}

	public String getValHorasSemana() {
		return valHorasSemana;
	}

	public void setValHorasSemana(String valHorasSemana) {
		this.valHorasSemana = valHorasSemana;
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
