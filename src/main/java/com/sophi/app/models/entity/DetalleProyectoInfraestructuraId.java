package com.sophi.app.models.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Embeddable;

@Embeddable
public class DetalleProyectoInfraestructuraId implements Serializable  {
	
	@Column(name = "cod_cliente")
	private Long codCliente;
	
	@Column(name = "cod_proyecto")
	private Long codProyecto;
	
	@Column(name = "cod_detalle_infraestructura")
	private Long codDetalleInfraestructura;
	
	@Column(name = "cod_estatus_proyecto")
	private Long codEstatusProyecto;

	public Long getCodCliente() {
		return codCliente;
	}

	public void setCodCliente(Long codCliente) {
		this.codCliente = codCliente;
	}

	public Long getCodProyecto() {
		return codProyecto;
	}

	public void setCodProyecto(Long codProyecto) {
		this.codProyecto = codProyecto;
	}

	public Long getCodDetalleInfraestructura() {
		return codDetalleInfraestructura;
	}

	public void setCodDetalleInfraestructura(Long codDetalleInfraestructura) {
		this.codDetalleInfraestructura = codDetalleInfraestructura;
	}

	public Long getCodEstatusProyecto() {
		return codEstatusProyecto;
	}

	public void setCodEstatusProyecto(Long codEstatusProyecto) {
		this.codEstatusProyecto = codEstatusProyecto;
	}
	
	
}
