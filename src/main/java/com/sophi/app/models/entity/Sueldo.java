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

@Entity
@Table(name = "RECURSOS_SUELDOS")
public class Sueldo implements Serializable  {

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_sueldo")
	private Long codSueldo;
	
	@Column(name = "imp_mensual_nomina")
	private Float impMensualNomina;
	
	@Column(name = "imp_mensual_asimilado")
	private Float impMensualAsimilado;
	
	@Column(name = "imp_mensual_bono")
	private Float impMensualBono;
	
	@Column(name = "imp_mensual_apoyo")
	private Float impMensualApoyo;
	
	@Column(name = "imp_mensual_otro")
	private Float impMensualOtro;
	
	@Column(name = "desc_mensual_otro")
	private String descMensualOtro;
	
	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	private Date fecRegistro;
	
	@PrePersist
	public void prePersist() {
		fecRegistro = new Date();
	}
	
	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "cod_recurso")
	private Recurso recurso;

	public Long getCodSueldo() {
		return codSueldo;
	}

	public void setCodSueldo(Long codSueldo) {
		this.codSueldo = codSueldo;
	}

	public Float getImpMensualNomina() {
		return impMensualNomina;
	}

	public void setImpMensualNomina(Float impMensualNomina) {
		this.impMensualNomina = impMensualNomina;
	}

	public Float getImpMensualAsimilado() {
		return impMensualAsimilado;
	}

	public void setImpMensualAsimilado(Float impMensualAsimilado) {
		this.impMensualAsimilado = impMensualAsimilado;
	}

	public Float getImpMensualBono() {
		return impMensualBono;
	}

	public void setImpMensualBono(Float impMensualBono) {
		this.impMensualBono = impMensualBono;
	}

	public Float getImpMensualApoyo() {
		return impMensualApoyo;
	}

	public void setImpMensualApoyo(Float impMensualApoyo) {
		this.impMensualApoyo = impMensualApoyo;
	}

	public Float getImpMensualOtro() {
		return impMensualOtro;
	}

	public void setImpMensualOtro(Float impMensualOtro) {
		this.impMensualOtro = impMensualOtro;
	}

	public String getDescMensualOtro() {
		return descMensualOtro;
	}

	public void setDescMensualOtro(String descMensualOtro) {
		this.descMensualOtro = descMensualOtro;
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
