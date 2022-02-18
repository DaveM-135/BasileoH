package com.sophi.app.models.dao;

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

import com.sophi.app.Utiles;
 import com.sophi.app.models.entity.Metas;

@Entity
@Table(name = "RESULTADOS_METAS")
public class RespuestaMeta implements Serializable {

	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_resultado_meta")
	private Long codResultadoMeta; 
	
	@Column(name = "cod_evaluacion_desempeno")
	private Long codEvaluacionDesempeno; 
	
	@Column(name = "cod_recurso")
	private Long codRecurso; 
	
	@Column(name = "cod_meta")
	private Long codMeta;
	
	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "cod_meta", insertable=false, updatable=false)
	Metas meta;
	
	@Column(name = "val_porcentaje")
	private Long valPorcentaje;
	
	@Column(name = "val_resultado_porcentaje")
	private Float valResultadoPorcentaje;
	
	@Column(name = "val_resultado")
	private Long valResultado;
	
	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	private Date fecRegistro;
	
	@PrePersist
	public void prePersist() {
		fecRegistro = new Utiles().getFechaActual();
	}

	public Long getCodResultadoMeta() {
		return codResultadoMeta;
	}

	public void setCodResultadoMeta(Long codResultadoMeta) {
		this.codResultadoMeta = codResultadoMeta;
	}

	public Long getCodEvaluacionDesempeno() {
		return codEvaluacionDesempeno;
	}

	public void setCodEvaluacionDesempeno(Long codEvaluacionDesempeno) {
		this.codEvaluacionDesempeno = codEvaluacionDesempeno;
	}

	public Long getCodRecurso() {
		return codRecurso;
	}

	public void setCodRecurso(Long codRecurso) {
		this.codRecurso = codRecurso;
	}

	public Long getCodMeta() {
		return codMeta;
	}

	public void setCodMeta(Long codMeta) {
		this.codMeta = codMeta;
	}

	public Metas getMeta() {
		return meta;
	}

	public void setMeta(Metas meta) {
		this.meta = meta;
	}

	public Long getValPorcentaje() {
		return valPorcentaje;
	}

	public void setValPorcentaje(Long valPorcentaje) {
		this.valPorcentaje = valPorcentaje;
	}

	public Float getValResultadoPorcentaje() {
		return valResultadoPorcentaje;
	}

	public void setValResultadoPorcentaje(Float valResultadoPorcentaje) {
		this.valResultadoPorcentaje = valResultadoPorcentaje;
	}

	public Long getValResultado() {
		return valResultado;
	}

	public void setValResultado(Long valResultado) {
		this.valResultado = valResultado;
	}

	public Date getFecRegistro() {
		return fecRegistro;
	}

	public void setFecRegistro(Date fecRegistro) {
		this.fecRegistro = fecRegistro;
	}
	

}
