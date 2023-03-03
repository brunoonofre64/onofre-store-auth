package br.com.onofrestore.auth.domain.entities;

import lombok.*;

import javax.persistence.*;
import javax.validation.constraints.Email;
import java.util.Set;

@Entity
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "TBL_USER")
@SequenceGenerator(name = "sequenceUser", sequenceName = "SQ_USER", allocationSize = 1)
public class UserEntity extends BaseEntity{

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "sequenceUser")
    @Column(name = "ID")
    private Long id;

    @Email(message = "EMAIL_FORMATO_INVALIDO")
    @Column(name = "EMAIL")
    private String email;

    @Column(name = "USUARIO", unique = true)
    private String username;

    @Column(name = "CPF")
    private String cpf;

    @Column(name = "AGE", nullable = false, length = 3)
    private String age;

    @Column(name = "NOME_COMPLETO")
    private String fullName;

    @Column(name = "SENHA")
    private String password;


    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "TBL_USER_ROLES",
            joinColumns = @JoinColumn(name = "USER_ID"),
            inverseJoinColumns = @JoinColumn(name = "ROLE_ID"))
    private Set<RoleEntity> roles;
}
