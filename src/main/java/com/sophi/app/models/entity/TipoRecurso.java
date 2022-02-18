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

@Entity
@Table(name = "CAT_TIPO_RECURSO")
public class TipoRecurso implements Serializable {

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_tipo_recurso")
	private Long codTipoRecurso;

	@Column(name = "desc_tipo_recurso")
	private String descTipoRecurso;

	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	private Date fecRegistro;

	public Long getCodTipoRecurso() {
		return codTipoRecurso;
	}

	public void setCodTipoRecurso(Long codTipoRecurso) {
		this.codTipoRecurso = codTipoRecurso;
	}

	public String getDescTipoRecurso() {
		return descTipoRecurso;
	}

	public void setDescTipoRecurso(String descTipoRecurso) {
		this.descTipoRecurso = descTipoRecurso;
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
