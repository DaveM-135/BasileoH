package com.sophi.app.models.entity;

import java.util.ArrayList;
import java.util.List;

public class AprobacionGastosDto {
	
	private List<AprobacionGastos> aprobaciongastos;
	
	public AprobacionGastosDto(List<AprobacionGastos> aprobaciongastos) {
		this.aprobaciongastos = aprobaciongastos;
	}
	
	public AprobacionGastosDto() {
		this.aprobaciongastos = new ArrayList<>();
	}
	
	public void addAprobacionGastos(AprobacionGastos aprobaciongastos) {
		this.aprobaciongastos.add(aprobaciongastos);
	}
	
	public List<AprobacionGastos> getAprobaciongastos() {
		return aprobaciongastos;
	}

	public void setAprobaciongastos(List<AprobacionGastos> aprobaciongastos) {
		this.aprobaciongastos = aprobaciongastos;
	}

}
