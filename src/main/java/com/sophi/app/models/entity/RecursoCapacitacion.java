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
import javax.persistence.Lob;
import javax.persistence.OneToOne;
import javax.persistence.PrePersist;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

import org.springframework.format.annotation.DateTimeFormat;

import com.sophi.app.Utiles;

@Entity
@Table(name = "RECURSOS_CAPACITACIONES")
public class RecursoCapacitacion implements Serializable {

	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_recurso_capacitacion")
	private Long codRecursoCapacitacion;
	
	@Column(name = "cod_capacitacion")
	private Long codCapacitacion;
	
	@OneToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "cod_capacitacion",insertable = false, updatable = false)
	private Capacitaciones capacitacion;
	
	@Column(name = "cod_recurso")
	private Long codRecurso;
	
	@Lob
    @Column(name = "desc_documento_evidencia", columnDefinition="BLOB")
	private byte[] descDocumentoEvidencia;
	
	@Column(name = "fec_inicio")
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date fecInicio;
	
	@Column(name = "fec_fin")
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date fecFin;
	
	@Column(name = "desc_estatus")
	private String descEstatus;
	
	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date fecRegistro;
	
	@PrePersist
	public void prePersist() {
		fecRegistro = new Utiles().getFechaActual();
	}

	public Long getCodRecursoCapacitacion() {
		return codRecursoCapacitacion;
	}

	public void setCodRecursoCapacitacion(Long codRecursoCapacitacion) {
		this.codRecursoCapacitacion = codRecursoCapacitacion;
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

	public byte[] getDescDocumentoEvidencia() {
		return descDocumentoEvidencia;
	}

	public void setDescDocumentoEvidencia(byte[] descDocumentoEvidencia) {
		this.descDocumentoEvidencia = descDocumentoEvidencia;
	}

	public Date getFecInicio() {
		return fecInicio;
	}

	public void setFecInicio(Date fecInicio) {
		this.fecInicio = fecInicio;
	}

	public Date getFecFin() {
		return fecFin;
	}

	public void setFecFin(Date fecFin) {
		this.fecFin = fecFin;
	}

	public String getDescEstatus() {
		return descEstatus;
	}

	public void setDescEstatus(String descEstatus) {
		this.descEstatus = descEstatus;
	}

	public Date getFecRegistro() {
		return fecRegistro;
	}

	public void setFecRegistro(Date fecRegistro) {
		this.fecRegistro = fecRegistro;
	}

	public Capacitaciones getCapacitacion() {
		return capacitacion;
	}

	public void setCapacitacion(Capacitaciones capacitacion) {
		this.capacitacion = capacitacion;
	}
	
	
}
