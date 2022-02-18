package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

import org.springframework.format.annotation.DateTimeFormat;

@Entity
@Table(name = "CAT_DETALLES_INFRAESTRUCTURA")
public class DetalleInfraestructura implements Serializable  {

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_detalle_infraestructura")
	private Long codDetalleInfraestructura;
	
	@Column(name = "desc_detalle")
	private String descDetalle;
	
	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	@DateTimeFormat(pattern = "yyyy-MM-dd hh:mm:ss")
	private Date fecRegistro;
	
	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "cod_infraestructura")
	private Infraestructura infraestructura;
	
	@OneToMany(mappedBy = "detalleInfraestructura")
    List<DetalleClienteInfraestructura> clientesInfraestructura;

	public Long getCodDetalleInfraestructura() {
		return codDetalleInfraestructura;
	}

	public void setCodDetalleInfraestructura(Long codDetalleInfraestructura) {
		this.codDetalleInfraestructura = codDetalleInfraestructura;
	}

	public String getDescDetalle() {
		return descDetalle;
	}

	public void setDescDetalle(String descDetalle) {
		this.descDetalle = descDetalle;
	}

	public Date getFecRegistro() {
		return fecRegistro;
	}

	public void setFecRegistro(Date fecRegistro) {
		this.fecRegistro = fecRegistro;
	}

	public Infraestructura getInfraestructura() {
		return infraestructura;
	}

	public void setInfraestructura(Infraestructura infraestructura) {
		this.infraestructura = infraestructura;
	}

	public static long getSerialversionuid() {
		return serialVersionUID;
	}

	public List<DetalleClienteInfraestructura> getClientesInfraestructura() {
		return clientesInfraestructura;
	}

	public void setClientesInfraestructura(List<DetalleClienteInfraestructura> clientesInfraestructura) {
		this.clientesInfraestructura = clientesInfraestructura;
	}

	
	
	
}
