package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.Objects;

import javax.persistence.Column;
import javax.persistence.Embeddable;

@Embeddable
public class DetalleClienteInfraestructuraId implements Serializable {

	private static final long serialVersionUID = 1L;
	
	@Column(name = "cod_cliente")
	private Long codCliente;
	
	@Column(name = "cod_detalle_infraestructura")
	private Long codDetalleInfraestructura;
	
	public DetalleClienteInfraestructuraId() {
		
	}

	public Long getCodCliente() {
		return codCliente;
	}

	public void setCodCliente(Long codCliente) {
		this.codCliente = codCliente;
	}

	public Long getCodDetalleInfraestructura() {
		return codDetalleInfraestructura;
	}

	public void setCodDetalleInfraestructura(Long codDetalleInfraestructura) {
		this.codDetalleInfraestructura = codDetalleInfraestructura;
	}

	public static long getSerialversionuid() {
		return serialVersionUID;
	}

	@Override
	public int hashCode() {
		return Objects.hash(codCliente,codDetalleInfraestructura);
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DetalleClienteInfraestructuraId detalleClienteInfraestructuraId = (DetalleClienteInfraestructuraId) o;
        return codCliente.equals(detalleClienteInfraestructuraId.codCliente) &&
        		codDetalleInfraestructura.equals(detalleClienteInfraestructuraId.codDetalleInfraestructura);
	}


}
