package com.yyj.api.model;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.*;

@Document
@Data
public class RefreshToken {
    @Id
    String id;
    @DocumentReference(lazy = true)
    private Youser owner;
}
