package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.Lob;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.persistence.Transient;

import org.springframework.format.annotation.DateTimeFormat;

@Entity
@Table(name = "RECURSOS_GASTO")
public class RecursoGasto implements Serializable{

	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_recurso_gasto")
	private Long codRecursoGasto;
	
	@OneToOne
	@JoinColumn(name = "cod_tipo_gasto")
	private TipoGasto tipoGasto;
	
	@Column(name = "cod_proyecto")
	private Long codProyecto;
	
	@Column(name = "cod_recurso")
	private Long codRecurso;
	
	@Column(name = "cod_cliente")
	private Long codCliente;
	
	@Column(name = "cod_estatus_proyecto")
	private Long codEstatusProyecto;
	
	@Column(name = "desc_comentario")
	private String descComentario;
	
	@Column(name = "fec_gasto")
	@Temporal(TemporalType.DATE)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date fecGasto;
	
	@Column(name = "imp_gasto")
	private float impGasto;
	
	@Lob
    @Column(name = "desc_comprobante", columnDefinition="BLOB")
    private byte[] comprobante;

	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	@DateTimeFormat(pattern = "yyyy-MM-dd hh:mm:ss")
	private Date fecRegistro;
	
	@Column(name = "cod_recurso_validador")
	private Long codRecursoValidador;
	
	@Column(name = "val_importe_validado")
	private Float valImporteValidado;
	    
	@Column(name = "fec_validacion")
	@Temporal(TemporalType.DATE)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date fecValidacion;
	
	@Transient
	private ProyectoRecurso proyectoRecurso;

	public String getDescComentario() {
		return descComentario;
	}

	public void setDescComentario(String descComentario) {
		this.descComentario = descComentario;
	}

	public Date getFecGasto() {
		return fecGasto;
	}

	public void setFecGasto(Date fecGasto) {
		this.fecGasto = fecGasto;
	}

	public float getImpGasto() {
		return impGasto;
	}

	public void setImpGasto(float impGasto) {
		this.impGasto = impGasto;
	}

	public byte[] getComprobante() {
		return comprobante;
	}

	public void setComprobante(byte[] comprobante) {
		this.comprobante = comprobante;
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

	public RecursoGasto() {
		
	}

	public ProyectoRecurso getProyectoRecurso() {
		return proyectoRecurso;
	}

	public void setProyectoRecurso(ProyectoRecurso proyectoRecurso) {
		this.proyectoRecurso = proyectoRecurso;
	}

	public Long getCodRecursoGasto() {
		return codRecursoGasto;
	}

	public void setCodRecursoGasto(Long codRecursoGasto) {
		this.codRecursoGasto = codRecursoGasto;
	}

	public TipoGasto getTipoGasto() {
		return tipoGasto;
	}

	public void setTipoGasto(TipoGasto tipoGasto) {
		this.tipoGasto = tipoGasto;
	}

	public Long getCodProyecto() {
		return codProyecto;
	}

	public void setCodProyecto(Long codProyecto) {
		this.codProyecto = codProyecto;
	}

	public Long getCodRecurso() {
		return codRecurso;
	}

	public void setCodRecurso(Long codRecurso) {
		this.codRecurso = codRecurso;
	}

	public Long getCodCliente() {
		return codCliente;
	}

	public void setCodCliente(Long codCliente) {
		this.codCliente = codCliente;
	}

	public Long getCodEstatusProyecto() {
		return codEstatusProyecto;
	}

	public void setCodEstatusProyecto(Long codEstatusProyecto) {
		this.codEstatusProyecto = codEstatusProyecto;
	}

	public Long getCodRecursoValidador() {
		return codRecursoValidador;
	}

	public void setCodRecursoValidador(Long codRecursoValidador) {
		this.codRecursoValidador = codRecursoValidador;
	}

	public Date getFecValidacion() {
		return fecValidacion;
	}

	public void setFecValidacion(Date fecValidacion) {
		this.fecValidacion = fecValidacion;
	}
	
	 public Float getValImporteValidado() {
		return valImporteValidado;
	}

	public void setValImporteValidado(Float valImporteValidado) {
		this.valImporteValidado = valImporteValidado;
	}
	
	
}
