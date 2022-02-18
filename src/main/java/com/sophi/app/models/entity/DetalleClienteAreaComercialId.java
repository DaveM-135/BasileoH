package com.sophi.app.models.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Embeddable;

@Embeddable
public class DetalleClienteAreaComercialId implements Serializable  {
	
	@Column(name = "cod_area_comercial")
	private Long codAreaComercia;
	
	@Column(name = "cod_cliente")
	private Long codCliente;

	public Long getCodAreaComercia() {
		return codAreaComercia;
	}

	public void setCodAreaComercia(Long codAreaComercia) {
		this.codAreaComercia = codAreaComercia;
	}

	public Long getCodCliente() {
		return codCliente;
	}

	public void setCodCliente(Long codCliente) {
		this.codCliente = codCliente;
	}
	
}
