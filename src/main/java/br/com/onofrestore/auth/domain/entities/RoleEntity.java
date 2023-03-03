package br.com.onofrestore.auth.domain.entities;

import lombok.*;

import javax.persistence.*;

@Entity
@Builder
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "TBL_ROLE")
@SequenceGenerator(name = "sequencerRole", sequenceName = "SQ_ROLE", allocationSize = 1)
public class RoleEntity extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "sequencerRole")
    @Column(name = "ID")
    private Long id;

    @Column(name = "PROFILE")
    private String profile;
}
