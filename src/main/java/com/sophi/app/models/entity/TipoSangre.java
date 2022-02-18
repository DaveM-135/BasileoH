package com.sophi.app.models.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "CAT_TIPO_SANGRE")
public class TipoSangre implements Serializable {

	private static final long serialVersionUID = 1L;
	
	@Id
	@Column(name = "cod_tipo_sangre")
	private Long codTipoSangre;
	
	@Column(name = "desc_tipo_sangre")
	private String descTipoSangre;

	public Long getCodTipoSangre() {
		return codTipoSangre;
	}

	public void setCodTipoSangre(Long codTipoSangre) {
		this.codTipoSangre = codTipoSangre;
	}

	public String getDescTipoSangre() {
		return descTipoSangre;
	}

	public void setDescTipoSangre(String descTipoSangre) {
		this.descTipoSangre = descTipoSangre;
	}
	
	

}
