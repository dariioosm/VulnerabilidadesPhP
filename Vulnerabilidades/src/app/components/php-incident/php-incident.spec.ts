import { ComponentFixture, TestBed } from '@angular/core/testing';
import { PhpIncident } from './php-incident';

describe('PhpIncident', () => {
  let component: PhpIncident;
  let fixture: ComponentFixture<PhpIncident>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [PhpIncident],
    }).compileComponents();

    fixture = TestBed.createComponent(PhpIncident);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
