package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.validation.constraints.NotEmpty;

@Entity
@Table(name = "CAT_CARGOS")
public class Cargo implements Serializable {

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_cargo")
	private Long codCargo;

	@NotEmpty(message = "Este dato no debe estar vacío")
	@Column(name = "desc_cargo")
	private String descCargo;

	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	private Date fecRegistro;

	public Long getCodCargo() {
		return codCargo;
	}

	public void setCodCargo(Long codCargo) {
		this.codCargo = codCargo;
	}

	public String getDescCargo() {
		return descCargo;
	}

	public void setDescCargo(String descCargo) {
		this.descCargo = descCargo;
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
