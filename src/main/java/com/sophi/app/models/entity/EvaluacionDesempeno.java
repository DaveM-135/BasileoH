package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToMany;
import javax.persistence.PrePersist;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.persistence.Transient;

import org.springframework.format.annotation.DateTimeFormat;

import com.sophi.app.Utiles;

@Entity
@Table(name = "EVALUACIONES_DESEMPENO")
public class EvaluacionDesempeno implements Serializable {

	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_evaluacion_desempeno")
	private Long codEvaluacionDesempeno; 
	
	@Column(name = "desc_evaluacion_desempeno")
	private String descEvaluacionDesempeno;
	
	@Column(name = "fec_periodo_inicio")
	@Temporal(TemporalType.DATE)
	@DateTimeFormat(pattern = "yyyy-MM")
	private Date fecPeriodoInicio;
	
	@Column(name = "fec_periodo_fin")
	@Temporal(TemporalType.DATE)
	@DateTimeFormat(pattern = "yyyy-MM")
	private Date fecPeriodoFin;
	
	@Column(name = "val_estatus")
	private Long valEstatus;
	
	@Column(name = "val_promedio_empresa")
	private Float valPromedioEmpresa;
	
	@Column(name = "fec_arranque")
	@Temporal(TemporalType.DATE)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date fecArranque;
	
	@Column(name = "fec_cierre")
	@Temporal(TemporalType.DATE)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date fecCierre;
	
	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	@DateTimeFormat(pattern = "yyyy-MM-dd hh:mm:ss")
	private Date fecRegistro;
	
	@OneToMany(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
	@JoinColumn(name = "cod_evaluacion_desempeno")
	private List<RecursoEvaluacion> recursosEvaluacion;
	
	@OneToMany(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
	@JoinColumn(name = "cod_evaluacion_desempeno")
	private List<RecursoEvaluador> recursosEvaluadores;
	
	@Transient
	private String descEstatus;
	
	@Transient
	private Float promedioCompetencias;
	
	@Transient
	private Float promedioMetas;
	
	@PrePersist
	public void prePersist() {
		fecRegistro = new Utiles().getFechaActual();
	}

	public Long getCodEvaluacionDesempeno() {
		return codEvaluacionDesempeno;
	}

	public void setCodEvaluacionDesempeno(Long codEvaluacionDesempeno) {
		this.codEvaluacionDesempeno = codEvaluacionDesempeno;
	}

	public String getDescEvaluacionDesempeno() {
		return descEvaluacionDesempeno;
	}

	public void setDescEvaluacionDesempeno(String descEvaluacionDesempeno) {
		this.descEvaluacionDesempeno = descEvaluacionDesempeno;
	}

	public Date getFecPeriodoInicio() {
		return fecPeriodoInicio;
	}

	public void setFecPeriodoInicio(Date fecPeriodoInicio) {
		this.fecPeriodoInicio = fecPeriodoInicio;
	}

	public Date getFecPeriodoFin() {
		return fecPeriodoFin;
	}

	public void setFecPeriodoFin(Date fecPeriodoFin) {
		this.fecPeriodoFin = fecPeriodoFin;
	}

	public Long getValEstatus() {
		return valEstatus;
	}

	public void setValEstatus(Long valEstatus) {
		this.valEstatus = valEstatus;
	}

	public Float getValPromedioEmpresa() {
		return valPromedioEmpresa;
	}

	public void setValPromedioEmpresa(Float valPromedioEmpresa) {
		this.valPromedioEmpresa = valPromedioEmpresa;
	}

	public Date getFecArranque() {
		return fecArranque;
	}

	public void setFecArranque(Date fecArranque) {
		this.fecArranque = fecArranque;
	}

	public Date getFecCierre() {
		return fecCierre;
	}

	public void setFecCierre(Date fecCierre) {
		this.fecCierre = fecCierre;
	}

	public Date getFecRegistro() {
		return fecRegistro;
	}

	public void setFecRegistro(Date fecRegistro) {
		this.fecRegistro = fecRegistro;
	}

	public String getDescEstatus() {
		return descEstatus;
	}

	public void setDescEstatus(String descEstatus) {
		this.descEstatus = descEstatus;
	}

	public List<RecursoEvaluacion> getRecursosEvaluacion() {
		return recursosEvaluacion;
	}

	public void setRecursosEvaluacion(List<RecursoEvaluacion> recursosEvaluacion) {
		this.recursosEvaluacion = recursosEvaluacion;
	}

	public List<RecursoEvaluador> getRecursosEvaluadores() {
		return recursosEvaluadores;
	}

	public void setRecursosEvaluadores(List<RecursoEvaluador> recursosEvaluadores) {
		this.recursosEvaluadores = recursosEvaluadores;
	}

	public Float getPromedioCompetencias() {
		return promedioCompetencias;
	}

	public void setPromedioCompetencias(Float promedioCompetencias) {
		this.promedioCompetencias = promedioCompetencias;
	}

	public Float getPromedioMetas() {
		return promedioMetas;
	}

	public void setPromedioMetas(Float promedioMetas) {
		this.promedioMetas = promedioMetas;
	}
	

}
