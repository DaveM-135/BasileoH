package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "CAT_CALENDARIO_SOPHI")
public class DiaFestivo implements Serializable {

	private static final long serialVersionUID = 1L;
	
	@Id
	@Column(name = "id")
	private Long id;

	@Column(name = "cod_dia_festivo")
	private Long codDiaFestivo;
	
	@Column(name = "fec_dia_festivo")
	private Date fecDiaFestivo;

	@Column(name = "desc_dia_festivo")
	private String descDiaFestivo;
	
	@Column(name = "val_es_nolaboral")
	private Long valEsNolaboral;
	
	@Column(name = "cod_tipo_dia_festivo")
	private Long codTipoDiaFestivo;
	
	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public Long getCodDiaFestivo() {
		return codDiaFestivo;
	}

	public void setCodDiaFestivo(Long codDiaFestivo) {
		this.codDiaFestivo = codDiaFestivo;
	}

	public Date getFecDiaFestivo() {
		return fecDiaFestivo;
	}

	public void setFecDiaFestivo(Date fecDiaFestivo) {
		this.fecDiaFestivo = fecDiaFestivo;
	}

	public String getDescDiaFestivo() {
		return descDiaFestivo;
	}

	public void setDescDiaFestivo(String descDiaFestivo) {
		this.descDiaFestivo = descDiaFestivo;
	}

	public Long getValEsNolaboral() {
		return valEsNolaboral;
	}

	public void setValEsNolaboral(Long valEsNolaboral) {
		this.valEsNolaboral = valEsNolaboral;
	}

	public Long getCodTipoDiaFestivo() {
		return codTipoDiaFestivo;
	}

	public void setCodTipoDiaFestivo(Long codTipoDiaFestivo) {
		this.codTipoDiaFestivo = codTipoDiaFestivo;
	}
	
}
