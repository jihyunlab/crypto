/**
 * @jest-environment node
 */
import { RandomNumberHelper } from '../../src/helpers/random-number.helper';

describe('Random number helper', () => {
  test(`Positive: randomNumber4()`, async () => {
    const randomNumber4 = await RandomNumberHelper.randomNumber4();

    expect(randomNumber4.toString().length).toBe(4);
  });

  test(`Positive: randomNumber6()`, async () => {
    const randomNumber6 = await RandomNumberHelper.randomNumber6();

    expect(randomNumber6.toString().length).toBe(6);
  });

  test(`Positive: randomNumber8()`, async () => {
    const randomNumber8 = await RandomNumberHelper.randomNumber8();

    expect(randomNumber8.toString().length).toBe(8);
  });
});
