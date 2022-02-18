package com.sophi.app.models.entity;

import java.util.ArrayList;
import java.util.List;

public class AprobacionHorasDto {
	private List<AprobacionHoras> aprobacionhoras;
	
	public AprobacionHorasDto(List<AprobacionHoras> aprobacionhoras) {
		this.aprobacionhoras = aprobacionhoras;
	}
	
	public AprobacionHorasDto() {
		this.aprobacionhoras = new ArrayList<>();
	}

	public void addAprobacionHoras(AprobacionHoras aprobacionhoras) {
		this.aprobacionhoras.add(aprobacionhoras);
	}

	public List<AprobacionHoras> getAprobacionhoras() {
		return aprobacionhoras;
	}

	public void setAprobacionhoras(List<AprobacionHoras> aprobacionhoras) {
		this.aprobacionhoras = aprobacionhoras;
	}
	
	
}
