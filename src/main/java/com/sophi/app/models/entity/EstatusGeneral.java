package com.sophi.app.models.entity;

public class EstatusGeneral {
	
	private Long codEstatusGeneral;
	private String descEstatusGeneral;
	
	public EstatusGeneral() {
		
	}
	
	public EstatusGeneral(Long codEstatusGeneral, String descEstatusGeneral) {
		super();
		this.codEstatusGeneral = codEstatusGeneral;
		this.descEstatusGeneral = descEstatusGeneral;
	}
	public Long getCodEstatusGeneral() {
		return codEstatusGeneral;
	}
	public void setCodEstatusGeneral(Long codEstatusGeneral) {
		this.codEstatusGeneral = codEstatusGeneral;
	}
	public String getDescEstatusGeneral() {
		return descEstatusGeneral;
	}
	public void setDescEstatusGeneral(String descEstatusGeneral) {
		this.descEstatusGeneral = descEstatusGeneral;
	}
	
	

}
