package br.com.onofrestore.auth.domain.entities;

import lombok.*;

import javax.persistence.*;
import javax.validation.constraints.Email;

@Entity
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "TBL_USER")
@SequenceGenerator(name = "sequenceUser", sequenceName = "SQ_USER", allocationSize = 1)
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "sequenceUser")
    @Column(name = "ID")
    private Long id;

    @Email(message = "Email inv\u00E1lido.")
    @Column(name = "EMAIL")
    private String email;

    @Column(name = "USUARIO", unique = true)
    private String username;

    @Column(name = "NOME_COMPLETO")
    private String fullName;

    @Column(name = "SENHA")
    private String password;
}
