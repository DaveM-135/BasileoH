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

import org.springframework.format.annotation.DateTimeFormat;

@Entity
@Table(name = "RECURSOS_GASTO")
public class AprobacionGastos implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_recurso_gasto")
	private Long codRecursoGasto;

	@OneToOne
    @JoinColumn(name = "cod_tipo_gasto", insertable = false, updatable = false)
    private TipoGasto tipogasto;
	
	@Column(name = "cod_proyecto")
	private Long codProyecto;
	
	@OneToOne
	@JoinColumn(name="cod_proyecto", insertable = false, updatable = false)
	private Proyecto proyecto;

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
    private Float impGasto;

    @Column(name = "desc_comprobante")
    private String descComprobante;

    @Column(name = "fec_registro")
    @Temporal(TemporalType.DATE)
    @DateTimeFormat(pattern = "yyyy-MM-dd")
    private Date fecRegistro;
    
    @Column(name = "fec_validacion")
    @Temporal(TemporalType.DATE)
    @DateTimeFormat(pattern = "yyyy-MM-dd")
    private Date fecValidacion;
    
    @Column(name = "cod_recurso_validador")
	private Long codRecursoValidador;
    
    @Column(name = "val_gasto_planeado")
    private Long valGastoPlaneado;
    
    @Lob
    @Column(name = "desc_comprobante", columnDefinition="BLOB", insertable = false, updatable=false)
	private byte[] foto;
    
    @Column(name = "val_importe_validado")
    private Float valImporteValidado;
    
    public Float getValImporteValidado() {
		return valImporteValidado;
	}

	public void setValImporteValidado(Float valImporteValidado) {
		this.valImporteValidado = valImporteValidado;
	}

	public Proyecto getProyecto() {
		return proyecto;
	}

	public void setProyecto(Proyecto proyecto) {
		this.proyecto = proyecto;
	}
    
    public byte[] getFoto() {
		return foto;
	}

	public void setFoto(byte[] foto) {
		this.foto = foto;
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

	@OneToOne
    @JoinColumn(name = "cod_recurso", insertable = false, updatable = false)
    private Recurso recurso;

    public static long getSerialversionuid() {
        return serialVersionUID;
    }    
    
    public Long getCodRecursoGasto() {
		return codRecursoGasto;
	}

	public void setCodRecursoGasto(Long codRecursoGasto) {
		this.codRecursoGasto = codRecursoGasto;
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

	public TipoGasto getTipogasto() {
		return tipogasto;
	}

	public void setTipogasto(TipoGasto tipogasto) {
		this.tipogasto = tipogasto;
	}

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

    public Float getImpGasto() {
        return impGasto;
    }

    public void setImpGasto(Float impGasto) {
        this.impGasto = impGasto;
    }

    public String getDescComprobante() {
        return descComprobante;
    }

    public void setDescComprobante(String descComprobante) {
        this.descComprobante = descComprobante;
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

	public Long getValGastoPlaneado() {
		return valGastoPlaneado;
	}

	public void setValGastoPlaneado(Long valGastoPlaneado) {
		this.valGastoPlaneado = valGastoPlaneado;
	}

    
}