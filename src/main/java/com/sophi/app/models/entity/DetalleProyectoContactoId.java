package com.sophi.app.models.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Embeddable;

@Embeddable
public class DetalleProyectoContactoId implements Serializable  {
	
	@Column(name = "cod_contacto")
	private Long codContacto;
	
	@Column(name = "cod_cliente")
	private Long codCliente;
	
	@Column(name = "cod_proyecto")
	private Long codProyecto;
	
	@Column(name = "cod_estatus_proyecto")
	private Long codEstatusProyecto;

	public Long getCodContacto() {
		return codContacto;
	}

	public void setCodContacto(Long codContacto) {
		this.codContacto = codContacto;
	}

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

	public Long getCodEstatusProyecto() {
		return codEstatusProyecto;
	}

	public void setCodEstatusProyecto(Long codEstatusProyecto) {
		this.codEstatusProyecto = codEstatusProyecto;
	}

}
