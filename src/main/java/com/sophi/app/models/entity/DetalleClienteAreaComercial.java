package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

@Entity
@Table(name = "DETALLE_CLIENTES_AREAS_COMERCIAL")
public class DetalleClienteAreaComercial implements Serializable  {

	private static final long serialVersionUID = 1L;

	@EmbeddedId
    private DetalleClienteAreaComercialId detalleClienteAreaComercialId;
	
	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	private Date fecRegistro;

	public DetalleClienteAreaComercialId getDetalleClienteAreaComercialId() {
		return detalleClienteAreaComercialId;
	}

	public void setDetalleClienteAreaComercialId(DetalleClienteAreaComercialId detalleClienteAreaComercialId) {
		this.detalleClienteAreaComercialId = detalleClienteAreaComercialId;
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
