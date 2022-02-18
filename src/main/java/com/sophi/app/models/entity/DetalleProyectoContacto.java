package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.MapsId;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

@Entity
@Table(name = "DETALLE_PROYECTOS_CONTACTOS")
public class DetalleProyectoContacto implements Serializable  {

	private static final long serialVersionUID = 1L;

	@EmbeddedId
    private DetalleProyectoContactoId detalleProyectoContactoId;
	
	@ManyToOne
	@MapsId("cod_contacto")
	@JoinColumn(name = "cod_contacto")
	Agenda agenda;
	
	@Column(name = "val_responsable_cliente")
	private Long valResponsableCliente;
	
	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	private Date fecRegistro;

	public DetalleProyectoContactoId getDetalleProyectoContactoId() {
		return detalleProyectoContactoId;
	}

	public void setDetalleProyectoContactoId(DetalleProyectoContactoId detalleProyectoContactoId) {
		this.detalleProyectoContactoId = detalleProyectoContactoId;
	}

	public Long getValResponsableCliente() {
		return valResponsableCliente;
	}

	public void setValResponsableCliente(Long valResponsableCliente) {
		this.valResponsableCliente = valResponsableCliente;
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
