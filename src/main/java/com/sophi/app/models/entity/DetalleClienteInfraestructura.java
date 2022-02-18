package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.MapsId;
import javax.persistence.PrePersist;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

import org.springframework.format.annotation.DateTimeFormat;

@Entity
@Table(name = "DETALLE_CLIENTES_INFRAESTRUCTURAS")
public class DetalleClienteInfraestructura implements Serializable  {

	private static final long serialVersionUID = 1L;
	
	@EmbeddedId
	DetalleClienteInfraestructuraId id;
	
	@ManyToOne
    @MapsId("cod_detalle_infraestructura")
    @JoinColumn(name = "cod_detalle_infraestructura")
    DetalleInfraestructura detalleInfraestructura;
	
	@ManyToOne
    @MapsId("cod_cliente")
    @JoinColumn(name = "cod_cliente")
    Cliente cliente;

	@Column(name = "desc_version")
	private String descVersion;
	
	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	@DateTimeFormat(pattern = "yyyy-MM-dd hh:mm:ss")
	private Date fecRegistro;
	
	@PrePersist
	public void prePersist() {
		fecRegistro = new Date();
	}

	public DetalleClienteInfraestructuraId getId() {
		return id;
	}

	public void setId(DetalleClienteInfraestructuraId id) {
		this.id = id;
	}

	public DetalleInfraestructura getDetalleInfraestructura() {
		return detalleInfraestructura;
	}

	public void setDetalleInfraestructura(DetalleInfraestructura detalleInfraestructura) {
		this.detalleInfraestructura = detalleInfraestructura;
	}

	public Cliente getCliente() {
		return cliente;
	}

	public void setCliente(Cliente cliente) {
		this.cliente = cliente;
	}

	public String getDescVersion() {
		return descVersion;
	}

	public void setDescVersion(String descVersion) {
		this.descVersion = descVersion;
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

	public DetalleClienteInfraestructura(DetalleClienteInfraestructuraId id,
			DetalleInfraestructura detalleInfraestructura, Cliente cliente, String descVersion, Date fecRegistro) {
		super();
		this.id = id;
		this.detalleInfraestructura = detalleInfraestructura;
		this.cliente = cliente;
		this.descVersion = descVersion;
		this.fecRegistro = fecRegistro;
	}
	
	public DetalleClienteInfraestructura() {
		
	}
}
